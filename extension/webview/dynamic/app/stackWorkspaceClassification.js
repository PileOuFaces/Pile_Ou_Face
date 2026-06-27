import {
  readSnapshotRegisterValue
} from './stackWorkspaceAnchoring.js';

import {
  countSeedSupport,
  seedOffsetRange
} from './stackWorkspaceCompaction.js';

import {
  collectSeedLabelEvidence,
  parseComparableScalarValue,
  readSeedObservedValue
} from './stackWorkspaceRuntimeEvidence.js';

import {
  mergeSeedContributors
} from './stackWorkspaceDebug.js';

import {
  normalizeSeed,
  seedIdentity
} from './stackWorkspaceSeeds.js';

import {
  BUFFER_STYLE_LABEL_RE,
  GENERIC_ARG_RE,
  GENERIC_LOCAL_RE,
  GENERIC_STACK_RE,
  GENERIC_VAR_RE,
  MAIN_ARGUMENT_NAMES,
  SOURCE_PRIORITY,
  SPECIAL_ARGUMENT_RE,
  clean,
  firstNonEmpty,
  isGenericName,
  isProtectedKind,
  isStrongBufferObservation,
  looksLikeArrayType,
  looksLikeBufferName,
  normalizeDisplayName,
  normalizeEntryKind,
  parseBigIntAddr,
  probableBufferFromObservation,
  readNumeric,
  readPositiveInt,
  resolveSourcePriority,
  sameFunction
} from './stackWorkspaceUtils.js';

export function reclassifyNegativeArgumentSpills({ seeds, observations, registerArguments, snapshot, wordSize, frameScope } = {}) {
  if (!frameScope?.ownerMatches) {
    return [...(Array.isArray(seeds) ? seeds : [])].map((seed) => normalizeSeed(seed)).filter(Boolean);
  }
  const currentSeeds = [...(Array.isArray(seeds) ? seeds : [])].map((seed) => normalizeSeed(seed)).filter(Boolean);
  const abiArguments = normalizeRegisterArguments(registerArguments, snapshot, wordSize);
  if (!abiArguments.length) return currentSeeds;

  const bufferFloor = currentSeeds
    .filter((seed) => normalizeEntryKind(seed?.kind) === 'buffer' && readNumeric(seed?.offset) < 0)
    .map((seed) => readNumeric(seed?.offset))
    .filter((offset) => Number.isFinite(offset))
    .sort((left, right) => left - right)[0] ?? null;

  const candidates = currentSeeds
    .filter((seed) => isPotentialNegativeArgumentSpillSeed(seed, observations, wordSize, bufferFloor))
    .sort((left, right) => readNumeric(left?.offset) - readNumeric(right?.offset));

  if (!candidates.length) return currentSeeds;

  const depthRanks = new Map(candidates.map((seed, index) => [seedIdentity(seed), index]));
  const scoredPairs = [];
  candidates.forEach((seed) => {
    abiArguments.forEach((argument, argIndex) => {
      const score = scoreNegativeArgumentSpillCandidate(seed, argument, {
        observations,
        wordSize,
        depthRank: depthRanks.get(seedIdentity(seed)) ?? 999,
        argIndex
      });
      if (score >= 360) {
        scoredPairs.push({ seed, argument, score });
      }
    });
  });

  const assignedSeedIds = new Set();
  const assignedArgumentIds = new Set();
  scoredPairs
    .sort((left, right) => right.score - left.score || left.argument.index - right.argument.index)
    .forEach(({ seed, argument }) => {
      const seedId = seedIdentity(seed);
      const argumentId = `${argument.location}:${argument.index}`;
      if (assignedSeedIds.has(seedId) || assignedArgumentIds.has(argumentId)) return;
      assignedSeedIds.add(seedId);
      assignedArgumentIds.add(argumentId);
      seed.kind = 'argument';
      if (readPositiveInt(seed?.size) > readPositiveInt(wordSize)) {
        seed.size = readPositiveInt(wordSize);
      }
      if (isGenericName(seed?.label) || matchesRegisterArgumentIdentity(seed?.label, argument)) {
        seed.label = '';
      }
      seed.seedContributors = mergeSeedContributors(seed?.seedContributors, [{
        offset: seed.offset,
        size: seed.size,
        kind: 'argument',
        source: 'derived',
        label: clean(argument?.name),
        isSynthetic: false
      }]);
    });

  return currentSeeds;
}

export function normalizeRegisterArguments(registerArguments, snapshot, wordSize) {
  return (Array.isArray(registerArguments) ? registerArguments : [])
    .map((argument, index) => ({
      index,
      location: clean(argument?.location).toLowerCase(),
      name: clean(argument?.name).toLowerCase(),
      size: readPositiveInt(argument?.size) ?? readPositiveInt(wordSize),
      value: readSnapshotRegisterValue(snapshot, clean(argument?.location).toLowerCase())
    }))
    .filter((argument) => argument.location && readPositiveInt(argument?.size));
}

export function isPotentialNegativeArgumentSpillSeed(seed, observations, wordSize, bufferFloor) {
  const offset = readNumeric(seed?.offset);
  const size = readPositiveInt(seed?.size);
  const kind = normalizeEntryKind(seed?.kind);
  if (!Number.isFinite(offset) || offset >= 0) return false;
  if (bufferFloor !== null && offset >= bufferFloor) return false;
  if (!size || size > readPositiveInt(wordSize)) return false;
  if (isProtectedKind(kind) || kind === 'buffer' || kind === 'padding') return false;

  const support = countSeedSupport(seed, observations);
  const hasExactEvidence = support.exact > 0 || resolveSourcePriority(seed?.source) >= SOURCE_PRIORITY.static;
  if (!hasExactEvidence) return false;

  const range = seedOffsetRange(seed);
  return Boolean(range && range.end <= 0);
}

export function scoreNegativeArgumentSpillCandidate(seed, argument, { observations, wordSize, depthRank, argIndex } = {}) {
  if (!seed || !argument) return -Infinity;
  const size = readPositiveInt(seed?.size) ?? 0;
  const argumentSize = readPositiveInt(argument?.size) ?? readPositiveInt(wordSize) ?? 0;
  if (!size || !argumentSize) return -Infinity;

  let score = 0;
  if (size === argumentSize) score += 240;
  else if (argumentSize === readPositiveInt(wordSize) && size === 4) score += 200;
  else return -Infinity;

  const labelEvidence = collectSeedLabelEvidence(seed, observations);
  if (labelEvidence.some((label) => matchesRegisterArgumentIdentity(label, argument))) {
    score += 1000;
  }

  const observedValue = readSeedObservedValue(seed, observations);
  if (observedValue !== null && argument.value !== null && observedValue === argument.value) {
    score += 900;
  }

  if (!labelEvidence.length || labelEvidence.every((label) => isGenericName(label))) {
    score += 80;
  }

  if (Number.isFinite(depthRank)) {
    score += Math.max(0, 180 - depthRank * 40);
  }
  score += Math.max(0, 40 - argIndex * 5);
  return score;
}

export function matchesRegisterArgumentIdentity(label, argument) {
  const cleanedLabel = clean(label).toLowerCase();
  const location = clean(argument?.location).toLowerCase();
  const name = clean(argument?.name).toLowerCase();
  if (!cleanedLabel || !location) return false;
  return cleanedLabel === location || cleanedLabel === name || cleanedLabel === `arg_${location}`;
}

export function classifyTrustedSeedKind({ rawKind, label, typeName, offset, functionName, bpRegister, meta } = {}) {
  const normalizedRole = normalizeEntryKind(rawKind);
  if (normalizedRole === 'saved_bp' || normalizedRole === 'return_address') return normalizedRole;

  const cleanedLabel = clean(label);
  const type = clean(typeName).toLowerCase();
  if (SPECIAL_ARGUMENT_RE.test(cleanedLabel)) return 'argument';
  if (normalizeDisplayName(cleanedLabel, normalizedRole, bpRegister) === 'modified') return 'modified';
  if (looksLikeBufferName(cleanedLabel) || looksLikeArrayType(type)) return 'buffer';
  if (normalizedRole === 'buffer') return 'buffer';
  if (normalizedRole === 'argument') return 'argument';
  if (normalizedRole === 'modified') return 'modified';
  if (normalizedRole === 'padding') return 'padding';
  if (normalizedRole === 'slot') return 'slot';
  if (normalizedRole === 'local') return 'local';
  if (resolveRestrictedAbiArgumentName({ offset, kind: normalizedRole, label }, functionName, bpRegister, meta)) return 'argument';
  return offset !== null && offset < 0 ? 'local' : normalizedRole;
}

export function classifyObservationSeedKind(observation, functionName, bpRegister, meta) {
  const kind = normalizeEntryKind(observation?.kind || observation?.role);
  const label = firstNonEmpty(observation?.modelName, observation?.label);
  const typeName = firstNonEmpty(observation?.modelType, observation?.typeName);

  if (kind === 'saved_bp' || kind === 'return_address') return kind;
  if (kind === 'padding') return 'padding';
  if (kind === 'modified') return 'modified';
  if (kind === 'argument') return 'argument';
  if (kind === 'buffer' && isStrongBufferObservation(observation)) return 'buffer';

  if (SPECIAL_ARGUMENT_RE.test(clean(label))) return 'argument';
  if (resolveRestrictedAbiArgumentName(observation, functionName, bpRegister, meta)) return 'argument';
  if (normalizeDisplayName(label, kind, bpRegister) === 'modified') return 'modified';
  if (looksLikeBufferName(label) || looksLikeArrayType(typeName) || (kind === 'buffer' && isStrongBufferObservation(observation))) return 'buffer';
  if (GENERIC_ARG_RE.test(clean(label))) return 'argument';
  if (GENERIC_VAR_RE.test(clean(label)) || BUFFER_STYLE_LABEL_RE.test(clean(label)) || GENERIC_LOCAL_RE.test(clean(label))) return 'local';
  if (GENERIC_STACK_RE.test(clean(label))) return 'slot';
  if (kind === 'local') return probableBufferFromObservation(observation) ? 'local' : 'local';
  if (kind === 'unknown' && observation?.offset !== null && observation.offset < 0 && observation?.sourcePriority >= SOURCE_PRIORITY.auto) return 'slot';
  return kind;
}

export function classifySyntheticObservationKind(observation, functionName, bpRegister, meta, gap) {
  const kind = classifyObservationSeedKind(observation, functionName, bpRegister, meta);
  if (!kind) return null;
  if (kind === 'saved_bp' || kind === 'return_address') return null;
  if (kind === 'padding') return 'padding';
  if (kind === 'buffer') {
    if (hasConcreteSyntheticBufferProof(observation)) return 'buffer';
    return classifyStructuralHoleFallback(observation, gap);
  }
  if (kind === 'argument') return isStrictStackSeedAllowed({ offset: observation?.offset, kind, functionName, bpRegister, meta }) ? 'argument' : null;
  if (kind === 'modified') return 'local';
  if (kind === 'local') return 'local';
  if (kind === 'slot') return observation?.sourcePriority >= SOURCE_PRIORITY.auto ? 'slot' : 'unknown';
  return observation?.sourcePriority >= SOURCE_PRIORITY.auto ? 'slot' : 'unknown';
}

export function hasConcreteSyntheticBufferProof(observation) {
  const sourcePriority = resolveSourcePriority(observation?.modelSource || observation?.source);
  if (sourcePriority < SOURCE_PRIORITY.static) return false;
  return Boolean(
    looksLikeBufferName(firstNonEmpty(observation?.modelName, observation?.label))
    || looksLikeArrayType(firstNonEmpty(observation?.modelType, observation?.typeName))
  );
}

export function classifyStructuralHoleFallback(observation, gap) {
  const size = readPositiveInt(observation?.size) ?? 0;
  const gapSize = gap ? Math.max(0, Number(gap.end || 0) - Number(gap.start || 0)) : 0;
  const hasMaterial = Boolean(
    clean(observation?.ascii)
    || clean(observation?.bytesHex)
    || clean(observation?.displayValue)
    || clean(observation?.rawValue)
    || observation?.recentWrite
    || observation?.changed
  );
  if (!hasMaterial) return 'padding';
  if (size <= 8 || (gapSize && size >= gapSize)) return 'padding';
  return 'unknown';
}

export function isStrictStackSeedAllowed({ offset, kind, functionName, bpRegister, meta } = {}) {
  const numericOffset = readNumeric(offset);
  const normalizedKind = normalizeEntryKind(kind);
  if (numericOffset === null) return false;
  if (normalizedKind === 'saved_bp' || normalizedKind === 'return_address') return true;
  if (numericOffset <= 0) return true;
  if (normalizedKind !== 'argument') return false;
  return Boolean(resolveRestrictedAbiArgumentName({ offset: numericOffset, kind }, functionName, bpRegister, meta));
}

export function resolveRestrictedAbiArgumentName(entryLike, functionName, bpRegister, meta) {
  const offset = readNumeric(entryLike?.offset);
  const label = firstNonEmpty(entryLike?.name, entryLike?.label, entryLike?.technicalLabel, entryLike?.modelName);
  const normalizedLabel = clean(normalizeDisplayName(label, entryLike?.kind, bpRegister));
  if (SPECIAL_ARGUMENT_RE.test(normalizedLabel)) return normalizedLabel;

  const isMainFunction = sameFunction(functionName, 'main');
  const is32BitBp = String(bpRegister || '').toLowerCase() === 'ebp' && Number(meta?.arch_bits || 32) === 32;
  if (!isMainFunction || !is32BitBp || !Number.isFinite(offset) || offset <= 0) return '';
  const candidate = MAIN_ARGUMENT_NAMES.get(Number(offset)) || '';
  if (!candidate) return '';

  const sourcePriority = resolveSourcePriority(entryLike?.source || entryLike?.modelSource);
  const semanticKind = normalizeEntryKind(entryLike?.kind || entryLike?.role);
  if (semanticKind === 'argument' || sourcePriority >= SOURCE_PRIORITY.static || GENERIC_ARG_RE.test(clean(label))) {
    return candidate;
  }
  return '';
}
