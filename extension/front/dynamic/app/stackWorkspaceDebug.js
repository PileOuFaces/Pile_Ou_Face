import {
  seedIdentity
} from './stackWorkspaceSeeds.js';

import {
  KIND_LABELS,
  clean,
  displayFunctionName,
  firstNonEmpty,
  formatCanonicalOffsetLabel,
  formatSourceLabel,
  isInternalSymbol,
  isProtectedKind,
  normalizeDisplayName,
  normalizeEntryKind,
  normalizeFunctionName,
  normalizeSource,
  observedRanges,
  pickAscii,
  pickBytes,
  pickHexValue,
  pickPointerValue,
  readConfidence,
  readNumeric,
  readPositiveInt,
  resolvePointedEntry,
  resolvePointedObservation,
  resolveRegisterArgumentLink,
  sameFunction,
  toHex,
  uniqueStrings
} from './stackWorkspaceUtils.js';

export function buildDetailPayload({
  entry,
  functionName,
  bpRegister,
  registerArguments,
  allEntries,
  allObservations
} = {}) {
  const observations = Array.isArray(entry?.observations) ? entry.observations : [];
  const primaryObservation = entry?.primaryObservation || null;
  const rows = [
    { label: 'Nom', value: entry?.name || 'slot' },
    { label: 'Categorie', value: KIND_LABELS[normalizeEntryKind(entry?.kind)] || 'local' },
    { label: 'Taille', value: `${entry?.size || 0} octet${Number(entry?.size || 0) > 1 ? 's' : ''}` },
    { label: 'Adresse', value: entry?.start !== null ? toHex(entry.start) : 'n/a' },
    { label: 'Offset', value: entry?.offsetLabel || 'n/a' }
  ];

  if (clean(entry?.typeName)) rows.push({ label: 'Type', value: entry.typeName });
  if (clean(entry?.typeSource)) rows.push({ label: 'Source du type', value: formatSourceLabel(entry.typeSource) });

  const slotValue = clean(primaryObservation?.displayValue || primaryObservation?.rawValue);
  if (slotValue) rows.push({ label: 'Valeur du slot', value: slotValue });

  const pointerValue = pickPointerValue(primaryObservation, entry?.size);
  const pointedEntry = pointerValue ? resolvePointedEntry(pointerValue, allEntries, entry) : null;
  const pointedObservation = !pointedEntry && pointerValue
    ? resolvePointedObservation(pointerValue, allObservations, entry)
    : null;
  const pointerLike = Boolean(pointerValue && (
    clean(primaryObservation?.pointerKind)
    || pointedEntry
    || pointedObservation
  ));
  if (pointerLike) rows.push({ label: 'Pointeur', value: pointerValue });
  if (pointedEntry) {
    rows.push({
      label: 'Memoire pointee',
      value: `${pointedEntry.name}${pointedEntry.offsetLabel ? ` (${pointedEntry.offsetLabel})` : ''}`
    });
    const pointedText = pickAscii(pointedEntry.observations);
    if (pointedText) rows.push({ label: 'Texte pointe', value: pointedText });
  } else if (pointedObservation) {
    const pointedName = firstNonEmpty(
      normalizeDisplayName(pointedObservation.modelName || pointedObservation.label, pointedObservation.kind, bpRegister),
      normalizeDisplayName(pointedObservation.label, pointedObservation.kind, bpRegister),
      pointerValue
    );
    rows.push({
      label: 'Memoire pointee',
      value: `${pointedName}${pointedObservation.offset !== null ? ` (${formatCanonicalOffsetLabel(bpRegister, pointedObservation.offset)})` : ''}`
    });
    const pointedText = firstNonEmpty(pickAscii([pointedObservation]), clean(pointedObservation.displayValue));
    if (pointedText) rows.push({ label: 'Texte pointe', value: pointedText });
  }

  const slotText = !pointerLike ? pickAscii(observations) : '';
  if (slotText) rows.push({ label: 'Texte du slot', value: slotText });

  const hexValue = pickHexValue(primaryObservation, observations);
  if (hexValue) rows.push({ label: 'Hex', value: hexValue });

  rows.push({ label: 'Source du nom', value: formatSourceLabel(entry?.nameSource) || 'fallback' });
  rows.push({ label: 'Fonction', value: functionName ? `${functionName}()` : 'n/a' });

  const registerLink = resolveRegisterArgumentLink(entry?.name, registerArguments);
  if (registerLink) rows.push({ label: 'Registre source', value: registerLink });

  const mutations = buildMutationSummary(entry?.flags);
  if (mutations.length) rows.push({ label: 'Mutation', value: mutations.join(', ') });

  if (entry?.returnAddressIntegrity?.corrupted) {
    rows.push({ label: 'Statut', value: 'corrompu' });
  } else if (entry?.returnAddressIntegrity?.suspect) {
    rows.push({ label: 'Statut', value: 'suspect' });
  }

  const bytes = pickBytes(observations);
  if (bytes) rows.push({ label: 'Bytes', value: bytes });

  const ranges = observedRanges(observations);
  if (ranges.length) rows.push({ label: 'Plage observee', value: ranges.join(', ') });

  const comments = uniqueStrings([
    ...entry.commentHints,
    ...(Array.isArray(observations) ? observations.map((item) => item.comment) : [])
  ]);
  if (comments.length) rows.push({ label: 'Commentaire', value: comments.join(' | ') });

  return {
    rows,
    subtitle: entry?.offsetLabel || KIND_LABELS[normalizeEntryKind(entry?.kind)] || 'slot'
  };
}

export function buildEntryDebugMetadata(entry) {
  const seedKinds = uniqueStrings((Array.isArray(entry?.seedContributors) ? entry.seedContributors : []).map((seed) => normalizeEntryKind(seed?.kind)));
  const seedSources = uniqueStrings((Array.isArray(entry?.seedContributors) ? entry.seedContributors : []).map((seed) => classifyDebugSource(seed?.source, seed?.isSynthetic, seed?.kind)));
  const observationCount = Array.isArray(entry?.observations) ? entry.observations.length : 0;
  const seedCount = Array.isArray(entry?.seedContributors) && entry.seedContributors.length ? entry.seedContributors.length : 1;
  return {
    identityKey: entry?.key || '',
    primarySource: classifyDebugSource(entry?.source, entry?.isSynthetic, entry?.kind),
    provenance: resolveEntryProvenance(entry),
    confidence: resolveEntryConfidence(entry),
    mergedObservationCount: Math.max(observationCount, seedCount ? 1 : 0),
    seedCount,
    seedKinds,
    seedSources
  };
}

export function buildFrameDebugModel({ controlSeeds, reliableStaticSeeds, compactedSeeds, syntheticEntries, finalizedEntries, logicalArguments, bpRegister } = {}) {
  return {
    seeds: [
      ...toDebugSeedSummaries(controlSeeds, 'control', bpRegister),
      ...toDebugSeedSummaries(reliableStaticSeeds, 'static', bpRegister),
      ...toDebugSeedSummaries(compactedSeeds, 'compacted', bpRegister),
      ...toDebugEntrySummaries(syntheticEntries, 'synthetic', bpRegister)
    ],
    items: toDebugItemSummaries(finalizedEntries),
    logicalArguments: toDebugLogicalArgumentSummaries(logicalArguments)
  };
}

export function normalizeSeedContributors(seedContributors, fallback) {
  const normalized = Array.isArray(seedContributors) && seedContributors.length
    ? seedContributors
    : [fallback];
  return normalized
    .map((seed) => ({
      offset: readNumeric(seed?.offset),
      size: readPositiveInt(seed?.size) ?? 1,
      kind: normalizeEntryKind(seed?.kind),
      source: normalizeSource(seed?.source),
      label: clean(seed?.label),
      confidence: readConfidence(seed?.confidence),
      isSynthetic: Boolean(seed?.isSynthetic)
    }))
    .filter((seed) => seed.offset !== null || seed.label || seed.kind !== 'unknown');
}

export function mergeSeedContributors(left, right) {
  const seeds = [
    ...(Array.isArray(left) ? left : []),
    ...(Array.isArray(right) ? right : [])
  ];
  const byIdentity = new Map();
  seeds.forEach((seed) => {
    const normalized = normalizeSeedContributors([seed], null)[0];
    if (!normalized) return;
    const identity = [
      normalized.kind,
      normalized.offset ?? 'none',
      normalized.size ?? 'none',
      normalized.source,
      normalized.label || 'nolabel',
      normalized.confidence ?? 'noconf',
      normalized.isSynthetic ? 'synthetic' : 'real'
    ].join(':');
    if (!byIdentity.has(identity)) byIdentity.set(identity, normalized);
  });
  return [...byIdentity.values()];
}

export function toDebugSeedSummaries(seeds, stage, bpRegister) {
  return (Array.isArray(seeds) ? seeds : []).map((seed) => ({
    stage,
    kind: normalizeEntryKind(seed?.kind),
    offset: formatCanonicalOffsetLabel(bpRegister || 'rbp', readNumeric(seed?.offset)) || '',
    size: readPositiveInt(seed?.size),
    source: classifyDebugSource(seed?.source, seed?.isSynthetic, seed?.kind),
    label: clean(seed?.label),
    key: seedIdentity(seed)
  }));
}

export function toDebugEntrySummaries(entries, stage, bpRegister) {
  return (Array.isArray(entries) ? entries : []).map((entry) => ({
    stage,
    kind: normalizeEntryKind(entry?.kind),
    offset: formatCanonicalOffsetLabel(entry?.bpRegister || bpRegister || 'rbp', readNumeric(entry?.offset)) || '',
    size: readPositiveInt(entry?.size),
    source: classifyDebugSource(entry?.source, entry?.isSynthetic, entry?.kind),
    label: clean(entry?.label),
    key: seedIdentity(entry)
  }));
}

export function toDebugItemSummaries(entries) {
  const sourceOrder = { static: 0, runtime: 1, control: 2, synthetic: 3 };
  return (Array.isArray(entries) ? entries : [])
    .map((entry) => ({
      key: clean(entry?.key),
      name: clean(entry?.name),
      kind: normalizeEntryKind(entry?.kind),
      offset: clean(entry?.offsetLabel),
      rawOffset: readNumeric(entry?.offset),
      size: readPositiveInt(entry?.size),
      source: clean(entry?.debug?.primarySource || classifyDebugSource(entry?.source, entry?.isSynthetic, entry?.kind)),
      mergedObservationCount: Number(entry?.debug?.mergedObservationCount ?? (Array.isArray(entry?.observations) ? entry.observations.length : 0)) || 0
    }))
    .sort((left, right) => {
      const leftSourceOrder = sourceOrder[left.source] ?? 9;
      const rightSourceOrder = sourceOrder[right.source] ?? 9;
      if (leftSourceOrder !== rightSourceOrder) return leftSourceOrder - rightSourceOrder;

      const leftOffset = left.rawOffset;
      const rightOffset = right.rawOffset;
      const leftPositive = Number.isFinite(leftOffset) && leftOffset > 0;
      const rightPositive = Number.isFinite(rightOffset) && rightOffset > 0;
      if (leftPositive !== rightPositive) return leftPositive ? -1 : 1;
      if (leftPositive && rightPositive && leftOffset !== rightOffset) return leftOffset - rightOffset;

      if (Number.isFinite(leftOffset) && Number.isFinite(rightOffset) && leftOffset !== rightOffset) {
        return rightOffset - leftOffset;
      }
      return String(left.name || '').localeCompare(String(right.name || ''));
    })
    .map(({ rawOffset, ...entry }) => entry);
}

export function toDebugLogicalArgumentSummaries(entries) {
  return (Array.isArray(entries) ? entries : []).map((entry) => ({
    name: clean(entry?.name),
    offset: clean(entry?.offsetLabel),
    size: readPositiveInt(entry?.size),
    storageKey: clean(entry?.storageKey),
    storageOffset: clean(entry?.storageOffsetLabel),
    register: clean(entry?.registerLocation)
  }));
}

export function classifyDebugSource(source, isSynthetic, kind) {
  if (isSynthetic) return 'synthetic';
  if (isProtectedKind(kind)) return 'control';
  const normalized = normalizeSource(source);
  if (normalized === 'source_c') return 'source_c';
  if (normalized === 'control') return 'control';
  if (normalized === 'heuristic' || normalized === 'runtime' || normalized === 'derived' || normalized === 'unknown') return 'runtime';
  return 'static';
}

export function buildDetailModel(entries, selectedSlotKey) {
  const selected = (Array.isArray(entries) ? entries : []).find((entry) => entry.key === String(selectedSlotKey || ''));
  if (!selected) return null;
  return {
    key: selected.key,
    title: selected.name,
    subtitle: selected.detailPayload?.subtitle || selected.offsetLabel || '',
    rows: Array.isArray(selected.detailPayload?.rows) ? selected.detailPayload.rows : [],
    badges: Array.isArray(selected.badges) ? selected.badges : []
  };
}

export function buildWorkspaceStatus(frameModel) {
  if (!frameModel || !Array.isArray(frameModel.entries) || !frameModel.entries.length) {
    const stepText = frameModel?.currentStep ? ` • etape ${frameModel.currentStep}` : '';
    return `${frameModel?.functionName || 'frame'}()${stepText} • frame vide`;
  }
  const bits = [`${frameModel.functionName}()`];
  if (frameModel.currentStep) bits.push(`etape ${frameModel.currentStep}`);
  bits.push(`${frameModel.entries.length} element${frameModel.entries.length > 1 ? 's' : ''}`);
  if (frameModel.frameSize) bits.push(`frame ${frameModel.frameSize}B`);
  return bits.join(' • ');
}

export function buildPanelTitle(panelMode, functionName) {
  if (panelMode === 'frame') {
    return `Stack Frame de ${clean(functionName) || 'fonction'}()`;
  }
  return '.text';
}

export function buildPanelSubtitle(panelMode, functionList, frameModel) {
  if (panelMode === 'frame') {
    return buildWorkspaceStatus(frameModel);
  }
  const count = Array.isArray(functionList) ? functionList.length : 0;
  if (!count) return 'Aucune fonction dans la trace.';
  const sourceBacked = functionList.some((entry) => entry?.sourceBacked);
  const scope = sourceBacked ? 'du code' : 'dans la trace';
  return `${count} fonction${count > 1 ? 's' : ''} ${scope}`;
}

export function buildFunctionList({ snapshots, meta, selectedFunction, currentFunction, includeHidden = false }) {
  const byName = new Map();
  const sourceFunctions = collectSourceFunctionEntries(meta);

  sourceFunctions.forEach((fn, index) => {
    const displayName = displayFunctionName(fn?.name || fn?.normalizedName || '');
    const normalized = normalizeFunctionName(fn?.normalizedName || displayName);
    if (!normalized || byName.has(normalized)) return;
    byName.set(normalized, {
      key: normalized,
      displayName,
      firstStep: null,
      stepCount: 0,
      addressLabel: '',
      symbolType: '',
      sourceOrder: Number.isFinite(Number(fn?.index)) ? Number(fn.index) : index,
      sourceBacked: true,
      source: 'source',
      rawNames: [displayName]
    });
  });

  (Array.isArray(snapshots) ? snapshots : []).forEach((snap, index) => {
    const displayName = displayFunctionName(snap?.func || '');
    const normalized = normalizeFunctionName(displayName);
    if (!normalized) return;
    const existing = byName.get(normalized) || {
      key: normalized,
      displayName,
      firstStep: index + 1,
      stepCount: 0,
      addressLabel: '',
      symbolType: '',
      sourceOrder: null,
      sourceBacked: false,
      source: 'runtime',
      rawNames: []
    };
    existing.rawNames = uniqueStrings([...(Array.isArray(existing.rawNames) ? existing.rawNames : []), displayName]);
    if (existing.firstStep === null || existing.firstStep === undefined) {
      existing.firstStep = index + 1;
    }
    existing.stepCount += 1;
    byName.set(normalized, existing);
  });

  const symbols = Array.isArray(meta?.functions) ? meta.functions : [];
  symbols.forEach((symbol) => {
    const rawName = String(symbol?.name || '').trim();
    const displayName = displayFunctionName(rawName);
    const normalized = normalizeFunctionName(displayName);
    if (!normalized) return;
    if (byName.has(normalized)) {
      const entry = byName.get(normalized);
      if (!entry.addressLabel && clean(symbol?.addr)) entry.addressLabel = clean(symbol.addr);
      if (!entry.symbolType && clean(symbol?.type)) entry.symbolType = clean(symbol.type);
      if (!entry.source) entry.source = 'symbol';
      entry.rawNames = uniqueStrings([...(Array.isArray(entry.rawNames) ? entry.rawNames : []), rawName, displayName]);
      return;
    }
    byName.set(normalized, {
      key: normalized,
      displayName,
      firstStep: null,
      stepCount: 0,
      addressLabel: clean(symbol?.addr) || '',
      symbolType: clean(symbol?.type) || '',
      sourceOrder: null,
      sourceBacked: false,
      source: 'symbol',
      rawNames: uniqueStrings([rawName, displayName])
    });
  });

  const mergedItems = [...byName.values()].map((entry) => markHiddenFunctionEntry(entry));
  const visibleItems = includeHidden ? mergedItems : mergedItems.filter((entry) => !entry.hidden);

  const items = visibleItems.sort((left, right) => {
    if (left.sourceBacked || right.sourceBacked) {
      const leftOrder = Number.isFinite(Number(left.sourceOrder)) ? Number(left.sourceOrder) : Number.MAX_SAFE_INTEGER;
      const rightOrder = Number.isFinite(Number(right.sourceOrder)) ? Number(right.sourceOrder) : Number.MAX_SAFE_INTEGER;
      if (leftOrder !== rightOrder) return leftOrder - rightOrder;
    }
    if (left.stepCount && !right.stepCount) return -1;
    if (!left.stepCount && right.stepCount) return 1;
    if (left.firstStep === null && right.firstStep !== null) return 1;
    if (left.firstStep !== null && right.firstStep === null) return -1;
    if (left.firstStep !== right.firstStep) return left.firstStep - right.firstStep;
    return left.displayName.localeCompare(right.displayName);
  });

  if (!items.length) {
    const fallback = displayFunctionName(selectedFunction || currentFunction || '');
    if (!fallback) return [];
    items.push({
      key: normalizeFunctionName(fallback),
      displayName: fallback,
      firstStep: 1,
      stepCount: 0,
      addressLabel: '',
      symbolType: '',
      sourceOrder: null,
      sourceBacked: false
    });
  }

  const selectedKey = normalizeFunctionName(selectedFunction || '');
  const currentKey = normalizeFunctionName(currentFunction || '');
  return items.map((entry) => ({
    ...entry,
    isSelected: entry.key === selectedKey,
    isCurrent: Boolean(currentKey && entry.key === currentKey)
  }));
}

export function markHiddenFunctionEntry(entry) {
  const rawNames = uniqueStrings([
    entry?.displayName,
    entry?.key,
    ...(Array.isArray(entry?.rawNames) ? entry.rawNames : [])
  ]);
  const hidden = !entry?.sourceBacked && rawNames.some((name) => isInternalSymbol(name));
  if (!hidden) {
    return {
      ...entry,
      hidden: false
    };
  }
  return {
    ...entry,
    hidden: true,
    hiddenReason: 'internal_runtime_or_linker_symbol'
  };
}

export function collectSourceFunctionEntries(meta) {
  const enrichment = meta?.source_enrichment && typeof meta.source_enrichment === 'object'
    ? meta.source_enrichment
    : null;
  if (!enrichment || enrichment.enabled !== true) return [];
  return (Array.isArray(enrichment.functions) ? enrichment.functions : [])
    .filter((entry) => normalizeFunctionName(entry?.normalizedName || entry?.name || ''));
}

export function resolveModelForFunction(model, activeFunction, currentFunction) {
  return resolveModelForFunctionSelection(model, activeFunction, currentFunction).model;
}

export function resolveModelForFunctionSelection(model, activeFunction, currentFunction) {
  const requestedName = displayFunctionName(activeFunction || '');
  const requestedFunction = canonicalFunctionIdentity(requestedName);
  const resolvedFunction = canonicalFunctionIdentity(model?.name || model?.functionName || '');
  const baseResult = {
    model: null,
    requestedFunction,
    resolvedFunction,
    rejectedFunction: '',
    rejectedReason: ''
  };

  if (!model || !Array.isArray(model.locals)) return baseResult;

  const idFunctions = collectModelItemFunctionIdentities(model);
  const mismatchedIdFunction = requestedFunction
    ? idFunctions.find((identity) => identity !== requestedFunction)
    : '';
  if (requestedFunction && mismatchedIdFunction) {
    return {
      ...baseResult,
      rejectedFunction: mismatchedIdFunction,
      rejectedReason: 'function_mismatch'
    };
  }

  if (requestedFunction) {
    if (resolvedFunction && resolvedFunction !== requestedFunction) {
      return {
        ...baseResult,
        rejectedFunction: resolvedFunction,
        rejectedReason: 'function_mismatch'
      };
    }
    if (resolvedFunction === requestedFunction || idFunctions.includes(requestedFunction)) {
      return {
        ...baseResult,
        model,
        resolvedFunction: resolvedFunction || requestedFunction
      };
    }
    if (!resolvedFunction && !idFunctions.length && sameFunction(requestedName, currentFunction)) {
      return {
        ...baseResult,
        model,
        resolvedFunction: requestedFunction
      };
    }
    return {
      ...baseResult,
      rejectedFunction: resolvedFunction || canonicalFunctionIdentity(currentFunction || ''),
      rejectedReason: 'function_mismatch'
    };
  }

  const modelName = displayFunctionName(model.name || model.functionName || '');
  if (sameFunction(modelName, currentFunction)) {
    return {
      ...baseResult,
      model,
      resolvedFunction: resolvedFunction || canonicalFunctionIdentity(currentFunction || '')
    };
  }
  return baseResult;
}

function collectModelItemFunctionIdentities(model) {
  const collections = [
    model?.items,
    model?.entries,
    model?.locals
  ];
  const identities = [];
  collections.forEach((collection) => {
    (Array.isArray(collection) ? collection : []).forEach((item) => {
      const identity = functionIdentityFromItemId(item?.id || item?.key);
      if (identity) identities.push(identity);
    });
  });
  return uniqueStrings(identities);
}

function functionIdentityFromItemId(value) {
  const raw = clean(value);
  if (!raw || !raw.includes(':')) return '';
  return canonicalFunctionIdentity(raw.split(':')[0]);
}

function canonicalFunctionIdentity(value) {
  let raw = clean(value).replace(/[<>]/g, '');
  if (!raw) return '';
  raw = raw.replace(/@.*/, '');
  raw = raw.replace(/\([^)]*\)\s*$/, '');
  raw = raw.replace(/\s+(?:0x[0-9a-f]+|\+0x[0-9a-f]+).*$/i, '');
  raw = raw.replace(/^(?:sym|symbol|func|function)\./i, '');
  raw = raw.replace(/^_+/, '');
  return raw.toLowerCase();
}

export function buildFrameSignature({ meta, functionName, bpRegister, bpAddress, currentStep, model, entries } = {}) {
  const signatureParts = {
    binary: clean(meta?.binary),
    archBits: Number(meta?.arch_bits) || 0,
    function: normalizeFunctionName(functionName || ''),
    bpRegister: String(bpRegister || 'rbp').toLowerCase(),
    bpAddress: bpAddress !== null ? toHex(bpAddress) : '',
    step: Number.isFinite(Number(currentStep)) ? Math.trunc(Number(currentStep)) : null,
    locals: (Array.isArray(model?.locals) ? model.locals : [])
      .map((local) => ({
        name: clean(local?.name),
        offset: readNumeric(local?.offset),
        size: readPositiveInt(local?.size),
        role: normalizeEntryKind(local?.role),
        type: clean(local?.cType)
      }))
      .sort((left, right) => {
        if ((left.offset ?? 0) !== (right.offset ?? 0)) return (left.offset ?? 0) - (right.offset ?? 0);
        return String(left.name || '').localeCompare(String(right.name || ''));
      }),
    entries: (Array.isArray(entries) ? entries : [])
      .map((entry) => ({
        offset: entry?.offset ?? null,
        size: entry?.size ?? null,
        kind: normalizeEntryKind(entry?.kind),
        synthetic: Boolean(entry?.isSynthetic)
      }))
      .sort((left, right) => {
        if ((left.offset ?? 0) !== (right.offset ?? 0)) return (left.offset ?? 0) - (right.offset ?? 0);
        return String(left.kind || '').localeCompare(String(right.kind || ''));
      })
  };
  return JSON.stringify(signatureParts);
}

export function buildMutationSummary(flags) {
  const out = [];
  const normalizedFlags = uniqueStrings(flags);
  if (normalizedFlags.includes('changed')) out.push('changed');
  if (normalizedFlags.includes('recent_write')) out.push('recent_write');
  if (normalizedFlags.includes('recent_read')) out.push('recent_read');
  return out;
}

export function resolveEntryProvenance(entry) {
  const kind = normalizeEntryKind(entry?.kind);
  if (isProtectedKind(kind)) return 'control';
  if (entry?.isSynthetic) return 'synthetic';
  const source = normalizeSource(entry?.source);
  if (source === 'source_c') return 'source_c';
  if (source === 'static' || source === 'mcp' || source === 'dwarf' || source === 'debug' || source === 'symbol') return 'static';
  if (source === 'runtime' || source === 'auto' || source === 'heuristic' || source === 'derived') return 'runtime';
  return source || 'runtime';
}

export function resolveEntryConfidence(entry) {
  const direct = readConfidence(entry?.confidence);
  if (direct !== null) return direct;
  const contributors = Array.isArray(entry?.seedContributors) ? entry.seedContributors : [];
  const contributorConfidence = contributors
    .map((seed) => readConfidence(seed?.confidence))
    .filter((value) => value !== null);
  if (contributorConfidence.length) return Math.max(...contributorConfidence);
  if (isProtectedKind(entry?.kind)) return 1;
  if (entry?.isSynthetic) return 0.5;
  return null;
}
