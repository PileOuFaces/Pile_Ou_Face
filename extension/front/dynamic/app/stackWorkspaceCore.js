import {
  buildFrameScope,
  filterRuntimeObservationsForFrame,
  filterSourceSimpleFrameEntries,
  isFinalEntryAllowedInFrame,
  recoverConcreteObjectExtents
} from './stackWorkspaceAnchoring.js';

import {
  reclassifyNegativeArgumentSpills
} from './stackWorkspaceClassification.js';

import {
  chooseEntryForObservation,
  compactCanonicalLayout
} from './stackWorkspaceCompaction.js';

import {
  annotateEntriesWithDiagnostics
} from './stackWorkspaceCorruption.js';

import {
  buildDetailModel,
  buildFrameDebugModel,
  buildFrameSignature,
  buildFunctionList,
  buildPanelSubtitle,
  buildPanelTitle,
  buildWorkspaceStatus,
  resolveModelForFunctionSelection
} from './stackWorkspaceDebug.js';

import {
  assignStableFallbackNames,
  buildLogicalArgumentEntries,
  finalizeDisplayEntry,
  finalizeEntryBase
} from './stackWorkspaceNaming.js';

import {
  buildRuntimeEvidence,
  buildRuntimeObservations
} from './stackWorkspaceRuntimeEvidence.js';

import {
  buildControlSeeds,
  buildReliableStaticSeeds,
  buildSyntheticSeeds,
  buildTrustedModelSeeds,
  mergeSeedLists,
  normalizeStaticSeeds
} from './stackWorkspaceSeeds.js';

import {
  clean,
  cleanValue,
  compareFrameEntries,
  countEntryBands,
  displayFunctionName,
  firstNonEmpty,
  normalizeEntryKind,
  normalizeSource,
  parseBigIntAddr,
  pickFallbackFunction,
  readConfidence,
  readNumeric,
  readPositiveInt,
  resolveBpRegister,
  resolveSourcePriority,
  sameFunction,
  toHex,
  uniqueStrings
} from './stackWorkspaceUtils.js';

export * from './stackWorkspaceAnchoring.js';
export * from './stackWorkspaceClassification.js';
export * from './stackWorkspaceCompaction.js';
export * from './stackWorkspaceCorruption.js';
export * from './stackWorkspaceDebug.js';
export * from './stackWorkspaceNaming.js';
export * from './stackWorkspaceRuntimeEvidence.js';
export * from './stackWorkspaceSeeds.js';
export * from './stackWorkspaceUtils.js';

export function buildStackWorkspaceModel({
  slots,
  snapshots,
  meta,
  currentStep,
  selectedFunction,
  selectedSlotKey,
  snapshot,
  analysis,
  diagnostics,
  mcp
} = {}) {
  const safeSnapshots = Array.isArray(snapshots) ? snapshots : [];
  const currentFunction = displayFunctionName(snapshot?.func || analysis?.function?.name || '');
  const requestedFunction = displayFunctionName(selectedFunction || '');
  const activeFunction = requestedFunction || currentFunction || pickFallbackFunction(safeSnapshots);
  const functionList = buildFunctionList({
    snapshots: safeSnapshots,
    meta,
    selectedFunction: requestedFunction,
    currentFunction
  });
  const hasFunctionSelection = Boolean(requestedFunction);
  const modelResolution = resolveModelForFunctionSelection(mcp?.model, activeFunction, currentFunction);
  const modelForFunction = modelResolution.model;
  const currentFrameMatchesSelection = !hasFunctionSelection || sameFunction(currentFunction, requestedFunction);
  const firstStepForActiveFunction = hasFunctionSelection
    ? findFirstStepForFunction(safeSnapshots, activeFunction)
    : null;
  const functionStepMismatch = hasFunctionSelection
    && Boolean(currentFunction)
    && !sameFunction(activeFunction, currentFunction);
  const mismatchEmptyState = functionStepMismatch
    ? buildFunctionStepMismatchEmptyState({
        activeFunction,
        currentFunction,
        firstStepForActiveFunction
      })
    : null;
  const rejectedSelectedFunctionModel = hasFunctionSelection
    && !modelForFunction
    && modelResolution.rejectedReason === 'function_mismatch';
  const shouldRenderEmptySelection = rejectedSelectedFunctionModel
    || (hasFunctionSelection && !modelForFunction && !currentFrameMatchesSelection);
  const frameModel = shouldRenderEmptySelection
    ? buildEmptyFrameModel({
        meta,
        currentStep,
        functionName: activeFunction || currentFunction
      })
    : hasFunctionSelection
    ? buildCanonicalFrameModel({
        slots,
        snapshots: safeSnapshots,
        meta,
        analysis,
        snapshot,
        currentStep,
        functionName: activeFunction || currentFunction,
        model: modelForFunction,
        diagnostics
      })
    : buildEmptyFrameModel({
        meta,
        currentStep,
        functionName: activeFunction || currentFunction
      });
  annotateFrameModelResolution(frameModel, {
    ...modelResolution,
    firstStepForActiveFunction,
    mismatchExplanation: mismatchEmptyState?.message || '',
    rejectedFunction: modelResolution.rejectedFunction || (shouldRenderEmptySelection ? currentFunction : ''),
    rejectedReason: modelResolution.rejectedReason || (shouldRenderEmptySelection ? 'function_mismatch' : '')
  });
  if (shouldRenderEmptySelection) {
    if (mismatchEmptyState) {
      frameModel.emptyState = mismatchEmptyState;
      frameModel.emptyText = mismatchEmptyState.message;
    } else {
      frameModel.emptyText = 'Aucun modele de stack disponible pour la fonction selectionnee.';
    }
  }
  const detailModel = buildDetailModel(frameModel.entries, selectedSlotKey, frameModel.functionName);
  const panelMode = hasFunctionSelection ? 'frame' : 'functions';

  return {
    functionList,
    frameModel,
    visualSlots: frameModel.entries,
    detailModel,
    hasFunctionSelection,
    panelMode,
    panelTitle: buildPanelTitle(panelMode, frameModel.functionName),
    panelSubtitle: buildPanelSubtitle(panelMode, functionList, frameModel),
    selectedSlotKey: detailModel?.key || '',
    statusText: buildWorkspaceStatus(frameModel)
  };
}

function annotateFrameModelResolution(frameModel, modelResolution) {
  if (!frameModel || !modelResolution) return frameModel;
  frameModel.debug = {
    ...(frameModel.debug || {}),
    requestedFunction: modelResolution.requestedFunction || '',
    resolvedFunction: modelResolution.model ? (modelResolution.resolvedFunction || '') : '',
    rejectedFunction: modelResolution.rejectedFunction || '',
    rejectedReason: modelResolution.rejectedReason || '',
    firstStepForActiveFunction: modelResolution.firstStepForActiveFunction !== null
      && modelResolution.firstStepForActiveFunction !== undefined
      && Number.isFinite(Number(modelResolution.firstStepForActiveFunction))
      ? Number(modelResolution.firstStepForActiveFunction)
      : null,
    mismatchExplanation: modelResolution.mismatchExplanation || ''
  };
  return frameModel;
}

const FRAME_READINESS_CONTROL_ROLES = new Set(['saved_bp', 'control', 'return_address', 'ret']);

// Whether the current invocation's own frame is actually set up at this
// step -- i.e. `mov rbp, rsp` has executed. Priority order:
// 1. An explicit backend signal (analysis.frame.frameReady), if ever added.
// 2. analysis.frame.slots, when it is a real array -- this is the backend's
//    own per-step Evidence, already gated server-side (only saved_bp/
//    return_address are emitted before the frame is ready), so any other
//    role in it is itself proof the frame is ready. This must be checked
//    BEFORE the frontend `slots`, because that top-level array can also
//    contain the raw, ungated snapshot.stack dump (legacy fallback,
//    injectControlSlots) merged in when analysis.frame.slots was empty --
//    that dump has no Evidence backing at all and must never be read as
//    "frame ready".
// 3. If analysis.frame exists (a real object) but has no slots array at
//    all -- e.g. hand-built fixtures that only care about model.locals --
//    fall back to the already-materialized per-step `slots`.
// 4. If analysis / analysis.frame is absent entirely, there is no Evidence
//    signal whatsoever for this step yet (e.g. analysisByStep not populated
//    for this step). Never trust the frontend `slots` fallback in that
//    case either -- it may just be the ungated snapshot.stack dump -- so
//    default to "not ready".
export function isFrameReadyAtCurrentStep(analysis, slots) {
  if (typeof analysis?.frame?.frameReady === 'boolean') return analysis.frame.frameReady;
  const hasNonControlRole = (role) => {
    const normalized = String(role || '').toLowerCase();
    return Boolean(normalized) && !FRAME_READINESS_CONTROL_ROLES.has(normalized);
  };
  if (Array.isArray(analysis?.frame?.slots)) {
    return analysis.frame.slots.some((slot) => hasNonControlRole(slot?.role));
  }
  if (!analysis?.frame || typeof analysis.frame !== 'object') return false;
  return (Array.isArray(slots) ? slots : []).some((slot) => (
    hasNonControlRole(slot?.semanticRole || slot?.role || slot?.kind)
  ));
}

function findFirstStepForFunction(snapshots, functionName) {
  if (!functionName || !Array.isArray(snapshots)) return null;
  const index = snapshots.findIndex((snap) => sameFunction(snap?.func, functionName));
  return index >= 0 ? index + 1 : null;
}

function formatFunctionCall(name) {
  const cleanName = displayFunctionName(name || '');
  return cleanName ? `${cleanName}()` : 'selected function';
}

function buildFunctionStepMismatchEmptyState({ activeFunction, currentFunction, firstStepForActiveFunction } = {}) {
  const activeLabel = formatFunctionCall(activeFunction);
  const currentLabel = formatFunctionCall(currentFunction);
  const hasStep = firstStepForActiveFunction !== null
    && firstStepForActiveFunction !== undefined
    && Number.isFinite(Number(firstStepForActiveFunction));
  const message = `${activeLabel} is selected, but the current trace step is still in ${currentLabel}.`;
  const guidance = `Go to a step inside ${activeLabel} to view its runtime stack frame.`;
  return {
    kind: 'function_step_mismatch',
    message,
    guidance,
    noExecutedStepText: hasStep ? '' : `No executed step for ${activeLabel} in this trace.`,
    actionLabel: hasStep ? `Jump to first ${activeLabel} step` : '',
    actionStep: hasStep ? Number(firstStepForActiveFunction) : null,
    activeFunction: displayFunctionName(activeFunction || ''),
    currentFunction: displayFunctionName(currentFunction || ''),
    firstStepForActiveFunction: hasStep ? Number(firstStepForActiveFunction) : null
  };
}

export function buildCanonicalFrameModel({
  slots,
  snapshots,
  meta,
  analysis,
  snapshot,
  currentStep,
  functionName,
  model,
  diagnostics
} = {}) {
  const bpRegister = resolveBpRegister(slots, meta);
  const spRegister = Number(meta?.arch_bits) === 32 ? 'esp' : 'rsp';
  const wordSize = Number(meta?.arch_bits) === 32 ? 4 : 8;
  const bpAddress = parseBigIntAddr(analysis?.frame?.basePointer)
    ?? parseBigIntAddr(analysis?.control?.savedBpAddr)
    ?? parseBigIntAddr(analysis?.frame?.savedBpAddr);
  const spAddress = parseBigIntAddr(analysis?.frame?.stackPointer);
  const registerArguments = Array.isArray(analysis?.frame?.registerArguments)
    ? analysis.frame.registerArguments
        .map((entry) => ({
          location: clean(entry?.location),
          name: clean(entry?.name),
          offset: readNumeric(entry?.offset),
          size: readPositiveInt(entry?.size),
          source: normalizeSource(entry?.source)
        }))
        .filter((entry) => entry.location || entry.name)
    : [];
  const rawObservations = buildRuntimeObservations(slots, bpAddress);

  const controlSeeds = buildControlSeeds({
    analysis,
    bpRegister,
    bpAddress,
    wordSize
  });
  // model.locals (mcp.model) is a trace-wide, per-function aggregate -- it
  // already contains locals/buffers/arguments the backend will only
  // actually resolve at a later step. Never surface them as seeds (and
  // never let them widen buildFrameScope below) before the frame itself is
  // established at the CURRENT step.
  const frameIsReady = isFrameReadyAtCurrentStep(analysis, slots);
  const trustedModelSeeds = frameIsReady
    ? buildTrustedModelSeeds({
        model,
        functionName,
        bpRegister,
        bpAddress,
        meta
      })
    : [];
  const preliminaryFrameScope = buildFrameScope({
    analysis,
    snapshot,
    currentStep,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    seeds: mergeSeedLists(controlSeeds, trustedModelSeeds),
    meta
  });
  const observations = filterRuntimeObservationsForFrame(rawObservations, preliminaryFrameScope);
  const reliableStaticSeeds = buildReliableStaticSeeds({
    analysis,
    observations,
    model,
    trustedModelSeeds,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    meta
  });
  const normalizedStaticSeeds = normalizeStaticSeeds({
    seeds: reliableStaticSeeds,
    observations,
    analysis,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    meta,
    registerArguments
  });
  const canonicalSeeds = compactCanonicalLayout({
    seeds: mergeSeedLists(controlSeeds, normalizedStaticSeeds),
    observations,
    analysis,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    meta
  });
  const frameScope = buildFrameScope({
    analysis,
    snapshot,
    currentStep,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    seeds: canonicalSeeds,
    meta
  });
  const recoveredSeeds = recoverConcreteObjectExtents({
    seeds: canonicalSeeds,
    observations,
    snapshots,
    analysis,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    meta,
    frameScope
  });
  const spillClassifiedSeeds = reclassifyNegativeArgumentSpills({
    seeds: recoveredSeeds,
    observations,
    registerArguments,
    snapshot,
    wordSize,
    frameScope
  });
  const runtimeEvidence = buildRuntimeEvidence({
    seeds: spillClassifiedSeeds,
    observations
  });
  const syntheticEntries = buildSyntheticSeeds({
    observations: runtimeEvidence.unmatchedObservations,
    existingEntries: runtimeEvidence.entries,
    functionName,
    bpRegister,
    bpAddress,
    meta,
    frameScope,
    frameIsReady
  });

  const rawEntryBases = [...runtimeEvidence.entries, ...syntheticEntries]
    .map((entry) => finalizeEntryBase(entry, {
      functionName,
      bpRegister,
      bpAddress,
      registerArguments,
      meta
    }))
    .filter(Boolean)
    .filter((entry) => isFinalEntryAllowedInFrame(entry, frameScope))
    .sort(compareFrameEntries);

  assignStableFallbackNames(rawEntryBases, {
    functionName,
    bpRegister,
    meta
  });

  const entryBases = filterSourceSimpleFrameEntries(rawEntryBases, {
    model
  });

  const logicalArguments = buildLogicalArgumentEntries({
    entries: entryBases,
    registerArguments,
    model,
    bpRegister,
    wordSize,
    functionName,
    meta
  });

  const finalizedEntries = entryBases.map((entry) => finalizeDisplayEntry(entry, {
    functionName,
    bpRegister,
    registerArguments,
    allEntries: entryBases,
    allObservations: rawObservations
  }));
  const diagnosticEntries = annotateEntriesWithDiagnostics(finalizedEntries, diagnostics);

  const frameSignature = buildFrameSignature({
    meta,
    functionName,
    bpRegister,
    bpAddress,
    currentStep,
    model,
    entries: diagnosticEntries
  });

  return {
    functionName: clean(functionName) || displayFunctionName(snapshot?.func || meta?.start_symbol || '') || 'frame',
    currentStep: Number.isFinite(Number(currentStep)) ? Math.trunc(Number(currentStep)) : null,
    bpRegister,
    spRegister,
    spMarker: spAddress !== null
      ? {
          register: spRegister.toUpperCase(),
          addressLabel: toHex(spAddress)
        }
      : {
          register: spRegister.toUpperCase(),
          addressLabel: ''
        },
    entries: diagnosticEntries,
    debug: buildFrameDebugModel({
        controlSeeds,
        reliableStaticSeeds: normalizedStaticSeeds,
        compactedSeeds: recoveredSeeds,
        syntheticEntries,
        finalizedEntries: diagnosticEntries,
        logicalArguments,
        bpRegister
      }),
    counts: countEntryBands(diagnosticEntries),
    frameSize: readPositiveInt(analysis?.frame?.frameSize),
    emptyText: 'Aucun element visible pour cette frame.',
    frameSignature,
    registerArguments,
    logicalArguments
  };
}

export function buildEmptyFrameModel({ meta, currentStep, functionName } = {}) {
  const bpRegister = Number(meta?.arch_bits) === 32 ? 'ebp' : 'rbp';
  const spRegister = Number(meta?.arch_bits) === 32 ? 'esp' : 'rsp';
  return {
    functionName: clean(functionName) || displayFunctionName(meta?.start_symbol || '') || 'frame',
    currentStep: Number.isFinite(Number(currentStep)) ? Math.trunc(Number(currentStep)) : null,
    bpRegister,
    spRegister,
    spMarker: { register: spRegister.toUpperCase(), addressLabel: '' },
    entries: [],
    debug: buildFrameDebugModel({
      controlSeeds: [],
      reliableStaticSeeds: [],
      syntheticEntries: [],
      finalizedEntries: [],
      bpRegister
    }),
    counts: countEntryBands([]),
    frameSize: null,
    emptyText: 'Choisissez une fonction pour afficher sa frame.',
    frameSignature: buildFrameSignature({ meta, functionName, bpRegister, bpAddress: null, currentStep, model: null, entries: [] }),
    registerArguments: [],
    logicalArguments: []
  };
}
