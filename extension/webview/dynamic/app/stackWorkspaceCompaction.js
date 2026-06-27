import {
  isSourceAnchoredSeed
} from './stackWorkspaceAnchoring.js';

import {
  resolveRestrictedAbiArgumentName
} from './stackWorkspaceClassification.js';

import {
  mergeSeedContributors
} from './stackWorkspaceDebug.js';

import {
  normalizeSeed
} from './stackWorkspaceSeeds.js';

import {
  KIND_PRIORITY,
  POINTER_HEX_RE,
  SOURCE_PRIORITY,
  SPECIAL_ARGUMENT_RE,
  addressesEqual,
  areKindsCompatible,
  areSizesCompatible,
  clean,
  firstNonEmpty,
  isGenericName,
  isProtectedKind,
  looksLikeArrayType,
  looksLikeBufferName,
  normalizeEntryKind,
  normalizeSource,
  observationRangeEnd,
  observationRangeStart,
  overlapByteCount,
  parseBigIntAddr,
  readNumeric,
  readPositiveInt,
  resolveSourcePriority,
  seedRangeEnd,
  seedRangeStart
} from './stackWorkspaceUtils.js';

export function compactCanonicalLayout({
  seeds,
  observations,
  analysis,
  functionName,
  bpRegister,
  bpAddress,
  wordSize,
  meta
} = {}) {
  const frameSize = readPositiveInt(analysis?.frame?.frameSize);
  const sorted = [...(Array.isArray(seeds) ? seeds : [])].sort(compareSeedsForLayout);
  return sorted.reduce((acc, seed) => {
    if (!seed) return acc;
    const previous = acc[acc.length - 1];
    if (previous && shouldCompactSeeds(previous, seed)) {
      acc[acc.length - 1] = mergeCompactedSeeds(previous, seed);
      return acc;
    }

    const conflicting = acc.find((candidate) => (
      seedsConflict(candidate, seed)
      && !shouldAllowNestedSeedCoexistence(candidate, seed, observations)
    ));
    if (conflicting) {
      const winner = chooseMoreTrustworthySeed(conflicting, seed, observations, {
        functionName,
        bpRegister,
        bpAddress,
        wordSize,
        meta
      });
      if (winner === conflicting) return acc;
      const index = acc.indexOf(conflicting);
      acc[index] = winner;
      return acc;
    }

    if (!isSeedInsideFrameBounds(seed, frameSize, wordSize)) return acc;
    acc.push(seed);
    return acc;
  }, []);
}

export function compactAdjacentSyntheticBufferEntries(entries) {
  return [...(Array.isArray(entries) ? entries : [])]
    .sort(compareSeedsForLayout)
    .reduce((acc, entry) => {
      const previous = acc[acc.length - 1];
      if (shouldMergeAdjacentSyntheticBuffers(previous, entry)) {
        acc[acc.length - 1] = mergeAdjacentSyntheticBufferEntries(previous, entry);
        return acc;
      }
      acc.push(entry);
      return acc;
    }, []);
}

export function shouldMergeAdjacentSyntheticBuffers(left, right) {
  if (!left || !right) return false;
  if (!left?.isSynthetic || !right?.isSynthetic) return false;
  if (normalizeEntryKind(left?.kind) !== 'buffer' || normalizeEntryKind(right?.kind) !== 'buffer') return false;
  const leftRange = seedOffsetRange(left);
  const rightRange = seedOffsetRange(right);
  if (!leftRange || !rightRange) return false;
  return leftRange.start === rightRange.end || rightRange.start === leftRange.end;
}

export function mergeAdjacentSyntheticBufferEntries(left, right) {
  const leftRange = seedOffsetRange(left);
  const rightRange = seedOffsetRange(right);
  const startOffset = Math.min(leftRange.start, rightRange.start);
  const endOffset = Math.max(leftRange.end, rightRange.end);
  const stronger = chooseMoreTrustworthySeed(left, right, [], {});
  return {
    ...stronger,
    offset: startOffset,
    size: endOffset - startOffset,
    start: parseBigIntAddr(stronger?.start) !== null && readNumeric(stronger?.offset) !== null
      ? parseBigIntAddr(stronger.start) - BigInt(readNumeric(stronger.offset)) + BigInt(startOffset)
      : null,
    end: parseBigIntAddr(stronger?.start) !== null && readNumeric(stronger?.offset) !== null
      ? parseBigIntAddr(stronger.start) - BigInt(readNumeric(stronger.offset)) + BigInt(endOffset)
      : null,
    observations: [
      ...(Array.isArray(left?.observations) ? left.observations : []),
      ...(Array.isArray(right?.observations) ? right.observations : [])
    ],
    seedContributors: mergeSeedContributors(left?.seedContributors, right?.seedContributors)
  };
}

export function compareSeedsForLayout(left, right) {
  const leftOffset = readNumeric(left?.offset);
  const rightOffset = readNumeric(right?.offset);
  if (leftOffset === null && rightOffset !== null) return 1;
  if (leftOffset !== null && rightOffset === null) return -1;
  if (leftOffset !== null && rightOffset !== null && leftOffset !== rightOffset) {
    return rightOffset - leftOffset;
  }

  const leftPriority = KIND_PRIORITY[normalizeEntryKind(left?.kind)] ?? 99;
  const rightPriority = KIND_PRIORITY[normalizeEntryKind(right?.kind)] ?? 99;
  if (leftPriority !== rightPriority) return leftPriority - rightPriority;

  const leftSize = readPositiveInt(left?.size) ?? 0;
  const rightSize = readPositiveInt(right?.size) ?? 0;
  return rightSize - leftSize;
}

export function seedOffsetRange(seed) {
  const offset = readNumeric(seed?.offset);
  const size = readPositiveInt(seed?.size);
  if (offset === null || size === null) return null;
  return {
    start: offset,
    end: offset + size
  };
}

export function isSeedInsideFrameBounds(seed, frameSize, wordSize) {
  const range = seedOffsetRange(seed);
  if (!range) return false;
  if (range.start < 0 && Number.isFinite(frameSize) && Math.abs(range.start) > frameSize) return false;
  if (normalizeEntryKind(seed?.kind) !== 'argument' && range.start > wordSize) return false;
  if (range.start < 0 && range.end > 0 && !isLikelyPointerSizedSeed(seed, wordSize)) return false;
  return true;
}

export function crossesFrameBase(seed) {
  const range = seedOffsetRange(seed);
  if (!range) return false;
  return range.start < 0 && range.end > 0;
}

export function isLikelyPointerSizedSeed(seed, wordSize) {
  return readPositiveInt(seed?.size) === readPositiveInt(wordSize);
}

export function isWeakStaticSeed(seed) {
  const label = clean(seed?.label);
  return !label || isGenericName(label) || normalizeEntryKind(seed?.kind) === 'slot' || normalizeEntryKind(seed?.kind) === 'unknown';
}

export function countSeedSupport(seed, observations, { functionName, bpRegister, meta } = {}) {
  const label = clean(seed?.label).toLowerCase();
  const support = {
    exact: 0,
    named: 0,
    overlap: 0
  };

  (Array.isArray(observations) ? observations : []).forEach((observation) => {
    if (readNumeric(observation?.offset) === readNumeric(seed?.offset)) {
      support.exact += 1;
    }

    const observationLabel = clean(firstNonEmpty(observation?.modelName, observation?.label)).toLowerCase();
    if (label && observationLabel && label === observationLabel) {
      support.named += 1;
    }

    if (isObservationCompatible(seed, observation)) {
      support.overlap += 1;
    }
  });

  if (!support.named && resolveRestrictedAbiArgumentName(seed, functionName, bpRegister, meta)) {
    support.named += 1;
  }

  return support;
}

export function isLikelyPointerSpillSeed(seed, observations, wordSize, registerArguments) {
  const kind = normalizeEntryKind(seed?.kind);
  const label = clean(seed?.label).toLowerCase();
  const typeName = clean(seed?.typeName).toLowerCase();
  const size = readPositiveInt(seed?.size) ?? 0;
  if (size <= wordSize) return false;

  const hasPointerObservation = (Array.isArray(observations) ? observations : []).some((observation) => (
    readNumeric(observation?.offset) === readNumeric(seed?.offset)
    && (clean(observation?.pointerKind) || POINTER_HEX_RE.test(clean(observation?.displayValue || observation?.rawValue)))
  ));

  const matchesRegisterArgument = Array.isArray(registerArguments) && registerArguments.some((argument) => {
    const name = clean(argument?.name).toLowerCase();
    return Boolean(
      name
      && (
        label === name
        || label === name.replace(/^arg_/, '')
        || (SPECIAL_ARGUMENT_RE.test(label) && name.includes(label))
      )
    );
  });

  return Boolean(
    kind === 'argument'
    || SPECIAL_ARGUMENT_RE.test(label)
    || label.startsWith('arg_')
    || typeName.includes('*')
    || matchesRegisterArgument
    || hasPointerObservation
  );
}

export function resolveNormalizedBufferSize(seed, observations, frameSize, wordSize) {
  const currentSize = readPositiveInt(seed?.size);
  if (currentSize === null) return null;

  const candidates = [currentSize];
  const seedLabel = clean(seed?.label).toLowerCase();
  const exactOffset = readNumeric(seed?.offset);

  (Array.isArray(observations) ? observations : []).forEach((observation) => {
    const observationSize = readPositiveInt(observation?.size);
    if (observationSize === null) return;
    const observationLabel = clean(firstNonEmpty(observation?.modelName, observation?.label)).toLowerCase();
    const sameLabel = Boolean(seedLabel && observationLabel && seedLabel === observationLabel);
    const exactStart = readNumeric(observation?.offset) === exactOffset;
    const trustedSource = resolveSourcePriority(observation?.modelSource || observation?.source) >= SOURCE_PRIORITY.static;
    const derivedSource = normalizeSource(observation?.modelSource || observation?.source) === 'derived'
      || normalizeSource(observation?.source) === 'derived';
    const strongBuffer = exactStart && (
      sameLabel
      || derivedSource
      || (trustedSource && (looksLikeBufferName(observationLabel) || looksLikeArrayType(firstNonEmpty(observation?.modelType, observation?.typeName))))
    );
    if (!strongBuffer) return;
    if (!exactStart && !isObservationCompatible(seed, observation)) return;
    candidates.push(observationSize);
  });

  const recovered = Math.max(...candidates);
  if (!Number.isFinite(recovered)) return currentSize;
  if (Number.isFinite(frameSize) && exactOffset !== null) {
    const maxAvailable = exactOffset < 0
      ? Math.abs(exactOffset)
      : Math.max(wordSize, frameSize + exactOffset);
    return Math.min(recovered, maxAvailable);
  }
  return recovered;
}

export function shouldDropWeakStaticSeed(seed, compactedSeeds, observations, frameSize, wordSize) {
  if (!isWeakStaticSeed(seed)) return false;
  if (!isSeedInsideFrameBounds(seed, frameSize, wordSize)) return true;
  const support = countSeedSupport(seed, observations);
  if (support.exact || support.named) return false;
  return (Array.isArray(compactedSeeds) ? compactedSeeds : []).some((candidate) => seedsConflict(candidate, seed));
}

export function shouldCompactSeeds(left, right) {
  if (!left || !right) return false;
  if (isProtectedKind(left?.kind) || isProtectedKind(right?.kind)) return false;
  if (isSourceAnchoredSeed(left) || isSourceAnchoredSeed(right)) return false;
  const leftRange = seedOffsetRange(left);
  const rightRange = seedOffsetRange(right);
  if (!leftRange || !rightRange) return false;
  const sameName = normalizedSeedName(left) && normalizedSeedName(left) === normalizedSeedName(right);
  const sameKind = normalizeEntryKind(left?.kind) === normalizeEntryKind(right?.kind);
  const overlapping = leftRange.start < rightRange.end && rightRange.start < leftRange.end;
  const touching = leftRange.end === rightRange.start || rightRange.end === leftRange.start;
  if (sameName) return overlapping || touching;
  return Boolean(sameKind && normalizeEntryKind(left?.kind) === 'buffer' && overlapping);
}

export function mergeCompactedSeeds(left, right) {
  const leftRange = seedOffsetRange(left);
  const rightRange = seedOffsetRange(right);
  const startOffset = Math.min(leftRange.start, rightRange.start);
  const endOffset = Math.max(leftRange.end, rightRange.end);
  const stronger = chooseMoreTrustworthySeed(left, right, [], {});
  const merged = {
    ...stronger,
    offset: startOffset,
    size: endOffset - startOffset,
    start: null,
    end: null,
    seedContributors: mergeSeedContributors(left?.seedContributors, right?.seedContributors)
  };
  if (parseBigIntAddr(stronger?.start) !== null && readNumeric(stronger?.offset) !== null) {
    const baseAddress = parseBigIntAddr(stronger.start) - BigInt(readNumeric(stronger.offset));
    merged.start = baseAddress + BigInt(startOffset);
    merged.end = merged.start + BigInt(merged.size);
  }
  return normalizeSeed(merged);
}

export function seedsConflict(left, right) {
  if (!left || !right) return false;
  const leftRange = seedOffsetRange(left);
  const rightRange = seedOffsetRange(right);
  if (!leftRange || !rightRange) return false;
  return leftRange.start < rightRange.end && rightRange.start < leftRange.end;
}

export function shouldAllowNestedSeedCoexistence(left, right, observations) {
  if (!left || !right) return false;
  const leftKind = normalizeEntryKind(left?.kind);
  const rightKind = normalizeEntryKind(right?.kind);
  if (leftKind === rightKind) return false;

  const bufferSeed = leftKind === 'buffer' ? left : rightKind === 'buffer' ? right : null;
  const nestedSeed = bufferSeed === left ? right : bufferSeed === right ? left : null;
  if (!bufferSeed || !nestedSeed) return false;

  const bufferRange = seedOffsetRange(bufferSeed);
  const nestedRange = seedOffsetRange(nestedSeed);
  if (!bufferRange || !nestedRange) return false;
  if (nestedRange.start < bufferRange.start || nestedRange.end > bufferRange.end) return false;

  const nestedKind = normalizeEntryKind(nestedSeed?.kind);
  if (nestedKind === 'modified') return true;
  if (nestedKind === 'argument' || nestedKind === 'padding' || nestedKind === 'slot' || nestedKind === 'unknown') {
    return false;
  }

  const support = countSeedSupport(nestedSeed, observations);
  if (support.exact > 0) return true;
  return !isWeakStaticSeed(nestedSeed);
}

export function chooseMoreTrustworthySeed(left, right, observations, context) {
  const leftScore = scoreStaticSeed(left, observations, context);
  const rightScore = scoreStaticSeed(right, observations, context);
  return rightScore > leftScore ? right : left;
}

export function scoreStaticSeed(seed, observations, { functionName, bpRegister, meta } = {}) {
  if (!seed) return -Infinity;
  const support = countSeedSupport(seed, observations, { functionName, bpRegister, meta });
  const sourceScore = resolveSourcePriority(seed?.source);
  const confidenceScore = Number(seed?.confidence || 0) * 100;
  const exactScore = support.exact * 220;
  const namedScore = support.named * 180;
  const overlapScore = support.overlap * 20;
  const weakPenalty = isWeakStaticSeed(seed) ? 120 : 0;
  const pointerBonus = isLikelyPointerSizedSeed(seed, readPositiveInt(seed?.size)) ? 20 : 0;
  return sourceScore + confidenceScore + exactScore + namedScore + overlapScore + pointerBonus - weakPenalty;
}

export function normalizedSeedName(seed) {
  const name = clean(seed?.label).toLowerCase();
  if (!name || isGenericName(name)) return '';
  return name;
}

export function findStructuralGapForObservation(observation, existingEntries) {
  const observationRange = seedOffsetRange(observation);
  if (!observationRange) return null;

  const realEntries = [...(Array.isArray(existingEntries) ? existingEntries : [])]
    .filter((entry) => !entry?.isSynthetic)
    .filter((entry) => seedOffsetRange(entry))
    .sort(compareSeedsForLayout);

  for (let index = 0; index < realEntries.length - 1; index += 1) {
    const upper = seedOffsetRange(realEntries[index]);
    const lower = seedOffsetRange(realEntries[index + 1]);
    if (!upper || !lower) continue;
    const gap = { start: lower.end, end: upper.start };
    if (gap.end <= gap.start) continue;
    if (observationRange.start >= gap.start && observationRange.end <= gap.end) {
      return gap;
    }
  }
  const lowest = realEntries[realEntries.length - 1];
  const lowestRange = seedOffsetRange(lowest);
  if (lowestRange && observationRange.end <= lowestRange.start) {
    return { start: observationRange.start, end: lowestRange.start };
  }
  return null;
}

export function chooseEntryForObservation(entries, observation) {
  const matches = (Array.isArray(entries) ? entries : [])
    .filter((entry) => isObservationCompatible(entry, observation))
    .sort((left, right) => compareEntryMatch(left, right, observation));
  return matches[0] ?? null;
}

export function compareEntryMatch(left, right, observation) {
  const leftScore = scoreEntryMatch(left, observation);
  const rightScore = scoreEntryMatch(right, observation);
  if (leftScore !== rightScore) return rightScore - leftScore;

  const leftSynthetic = left?.isSynthetic ? 1 : 0;
  const rightSynthetic = right?.isSynthetic ? 1 : 0;
  if (leftSynthetic !== rightSynthetic) return leftSynthetic - rightSynthetic;

  const leftPriority = resolveSourcePriority(left?.source);
  const rightPriority = resolveSourcePriority(right?.source);
  if (leftPriority !== rightPriority) return rightPriority - leftPriority;

  const leftKindPriority = KIND_PRIORITY[normalizeEntryKind(left?.kind)] ?? 99;
  const rightKindPriority = KIND_PRIORITY[normalizeEntryKind(right?.kind)] ?? 99;
  return leftKindPriority - rightKindPriority;
}

export function scoreEntryMatch(entry, observation) {
  let score = 0;
  if (!entry || !observation) return score;

  const exactOffset = entry?.offset !== null && entry.offset === observation?.offset;
  const exactAddress = addressesEqual(entry?.start, observation?.start);
  const sizeCompatible = areSizesCompatible(entry?.size, observation?.size);
  const kindCompatible = areKindsCompatible(entry?.kind, observation?.kind);
  const containedBufferMatch = allowsContainedBufferObservationMatch(entry, observation);
  const overlapBytes = overlapByteCount(
    seedRangeStart(entry),
    seedRangeEnd(entry),
    observationRangeStart(observation),
    observationRangeEnd(observation)
  );

  if (exactOffset) score += 1000;
  if (exactAddress) score += 700;
  if (sizeCompatible) score += 320;
  if (containedBufferMatch) score += 120;
  if (kindCompatible) score += 80;
  if (overlapBytes > 0) score += Math.min(40, overlapBytes);
  if (isSourceAnchoredSeed(entry)) score += 220;
  if (isProtectedKind(entry?.kind)) score += 50;

  const sizeDelta = Math.abs((readPositiveInt(entry?.size) ?? 0) - (readPositiveInt(observation?.size) ?? 0));
  score -= Math.min(40, sizeDelta);

  return score;
}

export function isObservationCompatible(entry, observation) {
  if (!entry || !observation) return false;
  const entryStart = seedRangeStart(entry);
  const entryEnd = seedRangeEnd(entry);
  const observationStart = observationRangeStart(observation);
  const observationEnd = observationRangeEnd(observation);
  const exactOffset = entry?.offset !== null && observation?.offset !== null && entry.offset === observation.offset;
  const exactAddress = addressesEqual(entryStart, observationStart);
  const overlapBytes = overlapByteCount(entryStart, entryEnd, observationStart, observationEnd);
  const sizeCompatible = areSizesCompatible(entry?.size, observation?.size);
  const kindCompatible = areKindsCompatible(entry?.kind, observation?.kind);
  const containedBufferMatch = allowsContainedBufferObservationMatch(entry, observation);

  if (isProtectedKind(entry?.kind)) {
    return Boolean(
      (exactAddress || exactOffset)
      && readPositiveInt(entry?.size) !== null
      && readPositiveInt(entry?.size) === readPositiveInt(observation?.size)
    );
  }

  if (exactOffset) return true;
  if (exactAddress && sizeCompatible) return true;
  if (overlapBytes <= 0) return false;
  if ((!sizeCompatible && !containedBufferMatch) || !kindCompatible) return false;

  const smallest = Math.min(readPositiveInt(entry?.size) ?? 0, readPositiveInt(observation?.size) ?? 0);
  if (smallest <= 0) return false;

  if (containedBufferMatch) {
    const sameRangeClass = entry?.offset !== null && observation?.offset !== null && Math.sign(entry.offset) === Math.sign(observation.offset);
    return sameRangeClass;
  }

  const substantialOverlap = overlapBytes >= Math.max(4, Math.floor(smallest / 2));
  const startInside = observationStart !== null && entryStart !== null && observationStart >= entryStart && observationStart < entryEnd;
  const sameRangeClass = entry?.offset !== null && observation?.offset !== null && Math.sign(entry.offset) === Math.sign(observation.offset);
  return Boolean(substantialOverlap && startInside && sameRangeClass);
}

export function allowsContainedBufferObservationMatch(entry, observation) {
  if (normalizeEntryKind(entry?.kind) !== 'buffer') return false;
  const entryStart = seedRangeStart(entry);
  const entryEnd = seedRangeEnd(entry);
  const observationStart = observationRangeStart(observation);
  const observationEnd = observationRangeEnd(observation);
  if (entryStart === null || entryEnd === null || observationStart === null || observationEnd === null) return false;
  return observationStart >= entryStart && observationEnd <= entryEnd;
}
