import {
  chooseEntryForObservation
} from './stackWorkspaceCompaction.js';

import {
  clean,
  cleanValue,
  firstNonEmpty,
  normalizeEntryKind,
  normalizeSource,
  parseBigIntAddr,
  readConfidence,
  readNumeric,
  readPositiveInt,
  resolveSourcePriority,
  toHex,
  uniqueStrings
} from './stackWorkspaceUtils.js';

export function collectSeedLabelEvidence(seed, observations) {
  const labels = [clean(seed?.label)];
  (Array.isArray(observations) ? observations : [])
    .filter((observation) => readNumeric(observation?.offset) === readNumeric(seed?.offset))
    .forEach((observation) => {
      labels.push(clean(observation?.label));
      labels.push(clean(observation?.modelName));
    });
  return uniqueStrings(labels.filter(Boolean).map((label) => label.toLowerCase()));
}

export function readSeedObservedValue(seed, observations) {
  const exactObservation = (Array.isArray(observations) ? observations : [])
    .filter((observation) => readNumeric(observation?.offset) === readNumeric(seed?.offset))
    .sort((left, right) => resolveSourcePriority(right?.source) - resolveSourcePriority(left?.source))[0] ?? null;
  if (!exactObservation) return null;
  return parseComparableScalarValue(firstNonEmpty(exactObservation?.rawValue, exactObservation?.displayValue));
}

export function parseComparableScalarValue(value) {
  const raw = clean(value);
  if (!raw) return null;
  const hex = parseBigIntAddr(raw);
  if (hex !== null) return hex;
  const numeric = readNumeric(raw);
  if (numeric === null) return null;
  return BigInt(Math.trunc(numeric));
}

export function buildRuntimeEvidence({ seeds, observations } = {}) {
  const entries = (Array.isArray(seeds) ? seeds : []).map((seed) => ({
    ...seed,
    observations: []
  }));
  const unmatchedObservations = [];

  (Array.isArray(observations) ? observations : []).forEach((observation) => {
    const target = chooseEntryForObservation(entries, observation);
    if (target) {
      target.observations.push(observation);
      return;
    }
    unmatchedObservations.push(observation);
  });

  return { entries, unmatchedObservations };
}

export function buildRuntimeObservations(slots, bpAddress) {
  return (Array.isArray(slots) ? slots : [])
    .map((slot, index) => {
      const offset = readNumeric(slot?.offsetFromBp);
      const size = readPositiveInt(slot?.size) ?? 1;
      const start = parseBigIntAddr(slot?.addressLabel)
        ?? (bpAddress !== null && offset !== null ? bpAddress + BigInt(offset) : null);
      const label = firstNonEmpty(slot?.technicalLabel, slot?.modelName);
      const modelName = clean(slot?.modelName);
      const modelRole = clean(slot?.modelRole);
      const semanticKind = normalizeEntryKind(slot?.semanticRole || slot?.rawRole || slot?.visualRole || modelRole);
      return {
        key: clean(slot?.key) || `runtime-${index}`,
        label,
        modelName,
        modelRole,
        modelType: clean(slot?.modelType),
        modelSource: normalizeSource(slot?.modelSource),
        modelConfidence: readNumeric(slot?.modelConfidence),
        role: semanticKind,
        kind: semanticKind,
        source: normalizeSource(slot?.source || slot?.modelSource),
        sourcePriority: resolveSourcePriority(slot?.source || slot?.modelSource),
        confidence: readConfidence(slot?.confidence) ?? readConfidence(slot?.modelConfidence),
        size,
        offset,
        start,
        end: start !== null ? start + BigInt(size) : null,
        addressLabel: start !== null ? toHex(start) : clean(slot?.addressLabel),
        displayValue: cleanValue(slot?.displayValue || slot?.rawValue),
        rawValue: cleanValue(slot?.rawValue),
        typeName: clean(slot?.modelType),
        comment: clean(slot?.comment),
        flags: uniqueStrings(slot?.flags),
        changed: Boolean(slot?.changed),
        recentWrite: Boolean(slot?.recentWrite),
        recentRead: Boolean(slot?.recentRead),
        bytesHex: clean(slot?.bytesHex),
        ascii: clean(slot?.ascii),
        pointerKind: clean(slot?.pointerKind),
        payloadRelated: Boolean(slot?.payloadRelated),
        activePointers: Array.isArray(slot?.activePointers) ? slot.activePointers.map((value) => clean(value)).filter(Boolean) : [],
        // Passthrough only, never derived/defaulted here -- lets
        // resolveReliableBackendRole (stackWorkspaceClassification.js) and
        // the backend-size checks (stackWorkspaceAnchoring.js) see the
        // same Evidence verdict that was on the original backend slot.
        classification: slot?.classification,
        evidenceClassification: slot?.evidenceClassification,
        size_exact: slot?.size_exact,
        observed_write_size: slot?.observed_write_size,
        estimated_bound: slot?.estimated_bound
      };
    })
    .filter((item) => item.offset !== null || item.start !== null);
}
