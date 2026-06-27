/**
 * @file main.js
 * @brief Entree webview pour le visualiseur.
 * @details Gere le bridge VS Code, l'etat, le filtre de steps et le rendu UI.
 */
import { dom } from './dom.js';
import { state } from './state.js';
import {
  resolveActiveDisasmFileLine,
  resolveDisasmJumpTarget,
  scrollDisasmToFileLine
} from './disasmPanel.js';
import {
  renderRuntimeDisasmEmpty,
  renderRuntimeEmptyState,
  renderRuntimeSnapshot
} from './runtimeRenderPipeline.js';
import {
  buildTraceDebugSnapshot,
  clearTraceDebugInspector,
  renderTraceDebugInspector
} from './debugTraceInspector.js';
import { diagnosticsForStep, mergeCrashDiagnostic, persistentCrashDiagnostics } from './diagnostics.js';
import { chooseInitStepForTrace, persistViewedStep, resolveTraceId } from './traceSession.js';
import { buildRegisterMap } from './utils.js';
import {
  normalizeStackPanelMode,
  persistStackPanelMode
} from './stackViewMode.js';

const vscode = window.POFHubMessageBus?.vscode || acquireVsCodeApi();
const STEP_STORAGE_KEY = 'pile-ou-face-current-step-by-trace';
const PREVIOUS_TRACE_ID_STORAGE_KEY = 'pile-ou-face-current-trace-id';
const STACK_VIEW_MODE_STORAGE_KEY = 'pile-ou-face-stack-detail-mode';

if (!window.POFHubMessageBus) vscode.postMessage({ type: 'ready' });

function applyModeClass() {
  if (window.POFHubMessageBus) return; // don't alter hub body classes
  const isDynamic = !state.simStackMode;
  document.body.classList.toggle('dynamic-view', isDynamic);
}

function normalizeStackViewMode(mode) {
  return mode === 'advanced' ? 'advanced' : 'frame';
}

function restoreStackViewMode() {
  try {
    return normalizeStackViewMode(localStorage.getItem(STACK_VIEW_MODE_STORAGE_KEY));
  } catch (_) {
    return 'frame';
  }
}

function persistStackViewMode(mode) {
  try {
    localStorage.setItem(STACK_VIEW_MODE_STORAGE_KEY, normalizeStackViewMode(mode));
  } catch (_) {
    /* ignore */
  }
}

function normalizePathForCompare(pathValue) {
  return String(pathValue || '').replace(/\\/g, '/');
}

function pathsEquivalent(pathA, pathB) {
  const a = normalizePathForCompare(pathA);
  const b = normalizePathForCompare(pathB);
  if (!a || !b) return false;
  if (a === b) return true;
  return a.endsWith(`/${b}`) || b.endsWith(`/${a}`);
}

function normalizeFunctionName(name) {
  const raw = String(name || '').trim();
  if (!raw) return '';
  return raw.replace(/^_+/, '').replace(/@.*/, '').replace(/<|>/g, '').toLowerCase();
}

function displayFunctionName(name) {
  const raw = String(name || '').trim();
  if (!raw) return '';
  const stripped = raw.replace(/@.*/, '').replace(/<|>/g, '');
  return stripped.startsWith('_') && stripped.length > 1 ? stripped.slice(1) : stripped;
}

function sameFunction(left, right) {
  const a = normalizeFunctionName(left);
  const b = normalizeFunctionName(right);
  return Boolean(a && b && a === b);
}

function parseAddress(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'string') return null;
  const text = value.trim().toLowerCase();
  if (!text) return null;
  if (text.startsWith('0x')) {
    const parsed = Number.parseInt(text, 16);
    return Number.isFinite(parsed) ? parsed : null;
  }
  if (/^[0-9a-f]+$/.test(text)) {
    const parsed = Number.parseInt(text, 16);
    return Number.isFinite(parsed) ? parsed : null;
  }
  if (/^\d+$/.test(text)) {
    const parsed = Number.parseInt(text, 10);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

// Normalize a runtime (rebased) address to the ELF-relative address space used
// by disasm listings.  For non-PIE binaries (base 0 or absent) returns the
// original string unchanged so callers never need a branch.
function toDisasmAddress(runtimeAddr) {
  const base = parseAddress(state.meta?.base);
  if (!base || base === 0) return runtimeAddr;
  const addr = parseAddress(runtimeAddr);
  if (addr === null) return runtimeAddr;
  const relative = addr - base;
  if (relative < 0) return runtimeAddr;
  return `0x${relative.toString(16)}`;
}

function getAnalysisForStep(step) {
  if (!step || !state.analysisByStep) return null;
  return state.analysisByStep[String(step)] ?? null;
}

function getMcpForStep(step) {
  if (!step || !state.mcp?.byStep) return null;
  return state.mcp.byStep[String(step)] ?? null;
}

function getEnrichmentForStep(step) {
  if (!step || !state.enrichment?.byStep) return null;
  return state.enrichment.byStep[String(step)] ?? null;
}

function getSnapshotRegisterMap(snapshot) {
  const registerItems = Array.isArray(snapshot?.registers)
    ? snapshot.registers
    : Array.isArray(snapshot?.regs)
    ? snapshot.regs
    : [];
  return Object.fromEntries(registerItems.map((entry) => [
    String(entry?.name || '').trim().toLowerCase(),
    entry?.value
  ]));
}

function readSnapshotBasePointer(snapshot) {
  const registers = getSnapshotRegisterMap(snapshot);
  return parseAddress(registers.rbp ?? registers.ebp);
}

function readPayloadBasePointer(payload) {
  return parseAddress(payload?.frame?.basePointer ?? payload?.analysis?.frame?.basePointer);
}

function resolveAnalysisFunctionName(payload) {
  return displayFunctionName(payload?.function?.name || '');
}

function resolveMcpFunctionName(payload) {
  return displayFunctionName(payload?.model?.name || payload?.analysis?.function?.name || '');
}

function resolveScopedStepPayload(stepMap, step, snapshot, expectedFunction, {
  resolvePayloadFunction,
  resolvePayloadBase
} = {}) {
  if (!step || !stepMap || typeof stepMap !== 'object') return null;
  const direct = stepMap[String(step)] ?? null;
  const expected = displayFunctionName(expectedFunction || snapshot?.func || '');
  if (!direct || !expected || typeof resolvePayloadFunction !== 'function') return direct;

  const directFunction = resolvePayloadFunction(direct);
  if (!directFunction || sameFunction(directFunction, expected)) {
    return direct;
  }

  const snapshotBp = readSnapshotBasePointer(snapshot);
  let bestPayload = null;
  let bestScore = -Infinity;

  Object.entries(stepMap).forEach(([rawStep, payload]) => {
    const candidateStep = Number(rawStep);
    if (!Number.isFinite(candidateStep) || !payload) return;

    const candidateFunction = resolvePayloadFunction(payload);
    if (!candidateFunction || !sameFunction(candidateFunction, expected)) return;

    let score = 0;
    const candidateBp = typeof resolvePayloadBase === 'function'
      ? resolvePayloadBase(payload)
      : null;

    if (snapshotBp !== null && candidateBp !== null) {
      if (candidateBp === snapshotBp) score += 100000;
      else score -= 1000;
    }

    score -= Math.abs(candidateStep - step) * 100;
    if (candidateStep <= step) score += 1;

    if (score > bestScore) {
      bestScore = score;
      bestPayload = payload;
    }
  });

  return bestPayload || direct;
}

function getScopedAnalysisForStep(step, snapshot, expectedFunction) {
  return resolveScopedStepPayload(state.analysisByStep, step, snapshot, expectedFunction, {
    resolvePayloadFunction: resolveAnalysisFunctionName,
    resolvePayloadBase: readPayloadBasePointer
  });
}

function getScopedMcpForStep(step, snapshot, expectedFunction) {
  return resolveScopedStepPayload(state.mcp?.byStep, step, snapshot, expectedFunction, {
    resolvePayloadFunction: resolveMcpFunctionName,
    resolvePayloadBase: readPayloadBasePointer
  });
}

function buildVisibleSteps() {
  if (state.simStackMode || state.showAllTrace || !state.selectedFunction) {
    return state.snapshots.map((_snap, index) => index + 1);
  }
  const filtered = state.snapshots
    .map((snap, index) => ({ snap, step: index + 1 }))
    .filter(({ snap }) => sameFunction(snap?.func, state.selectedFunction))
    .map(({ step }) => step);
  return filtered.length ? filtered : state.snapshots.map((_snap, index) => index + 1);
}

function findNearestStepForFunction(functionName, referenceStep) {
  const candidates = state.snapshots
    .map((snap, index) => ({ snap, step: index + 1 }))
    .filter(({ snap }) => sameFunction(snap?.func, functionName))
    .map(({ step }) => step);
  if (!candidates.length) return null;
  if (candidates.includes(referenceStep)) return referenceStep;
  let best = candidates[0];
  let bestDistance = Math.abs(best - referenceStep);
  candidates.forEach((step) => {
    const distance = Math.abs(step - referenceStep);
    if (distance < bestDistance || (distance === bestDistance && step < best)) {
      best = step;
      bestDistance = distance;
    }
  });
  return best;
}

function rebuildVisibleSteps() {
  state.visibleSteps = buildVisibleSteps();
}

function ensureCurrentStepVisible() {
  if (!state.visibleSteps.length) {
    state.currentStep = 1;
    return;
  }
  if (!state.visibleSteps.includes(state.currentStep)) {
    state.currentStep = state.visibleSteps[0];
  }
}

function findVisibleIndexForStep(step) {
  const index = state.visibleSteps.indexOf(step);
  return index >= 0 ? index + 1 : 1;
}

function clampVisibleIndex(index) {
  const total = state.visibleSteps.length || 1;
  if (index < 1) return 1;
  if (index > total) return total;
  return index;
}

function setStepFromVisibleIndex(index) {
  const safeIndex = clampVisibleIndex(index);
  state.currentStep = state.visibleSteps[safeIndex - 1] ?? 1;
}

function jumpToTraceStep(step, options = {}) {
  const targetStep = Math.trunc(Number(step));
  if (!Number.isFinite(targetStep) || targetStep < 1 || targetStep > state.snapshots.length) return;
  state.currentStep = targetStep;
  state.selectedStackSlotKey = null;
  rebuildVisibleSteps();
  ensureCurrentStepVisible();
  if (options.rerender !== false) {
    updateUI({ requestAnalysis: false });
  }
}

function mergeFunctionRangeEntry(map, name, start, end) {
  const normalized = normalizeFunctionName(name);
  if (!normalized) return;
  const current = map.get(normalized) || {
    name: displayFunctionName(name),
    rangeStart: null,
    rangeEnd: null
  };
  if (start !== null && (current.rangeStart === null || start < current.rangeStart)) {
    current.rangeStart = start;
  }
  if (end !== null && (current.rangeEnd === null || end > current.rangeEnd)) {
    current.rangeEnd = end;
  }
  if (!current.name && name) current.name = displayFunctionName(name);
  map.set(normalized, current);
}

function buildFunctionRangeIndex() {
  const map = new Map();
  state.snapshots.forEach((snap, index) => {
    const step = Number(snap?.step) || index + 1;
    const analysis = getAnalysisForStep(step);
    const functionInfo = analysis?.function && typeof analysis.function === 'object' ? analysis.function : {};
    const name = displayFunctionName(functionInfo.name || snap?.func || '');
    const start = parseAddress(functionInfo.range_start || functionInfo.addr);
    const end = parseAddress(functionInfo.range_end);
    mergeFunctionRangeEntry(map, name, start, end);
  });

  const functionSymbols = Array.isArray(state.meta?.functions) ? state.meta.functions : [];
  functionSymbols.forEach((symbol) => {
    const name = displayFunctionName(symbol?.name || '');
    const start = parseAddress(symbol?.addr);
    const size = parseAddress(symbol?.size);
    const end = start !== null && size !== null && size > 0 ? start + size : null;
    mergeFunctionRangeEntry(map, name, start, end);
  });

  return map;
}

function findFunctionRangeForAddress(rangeIndex, targetAddr) {
  if (!(rangeIndex instanceof Map) || targetAddr === null) return null;
  let best = null;
  for (const entry of rangeIndex.values()) {
    if (entry.rangeStart === null) continue;
    if (targetAddr < entry.rangeStart) continue;
    if (entry.rangeEnd !== null && targetAddr >= entry.rangeEnd) continue;
    if (!best || entry.rangeStart > best.rangeStart) {
      best = entry;
    }
  }
  return best;
}

function parseCallTargetAddress(entry) {
  const operand = String(entry?.operands || '').trim();
  if (!operand) return null;
  const match = operand.match(/(0x[0-9a-f]+|[0-9a-f]{4,})/i);
  return match ? parseAddress(match[1]) : null;
}

function buildAsmFunctionHeaders(entries, rangeIndex) {
  const headers = {};
  entries.forEach((entry) => {
    const addr = parseAddress(entry?.addr);
    if (addr === null) return;
    const fn = findFunctionRangeForAddress(rangeIndex, addr);
    if (!fn?.name || fn.rangeStart === null || fn.rangeStart !== addr) return;
    headers[addr.toString(16)] = displayFunctionName(fn.name);
  });
  return headers;
}

function buildDisasmEntriesForRender() {
  if (!Array.isArray(state.disasmLines) || !state.disasmLines.length) {
    return { entries: [], functionHeaders: {} };
  }
  if (state.simStackMode) {
    return {
      entries: state.disasmLines,
      functionHeaders: {}
    };
  }

  const snap = state.snapshots[state.currentStep - 1] ?? null;
  const targetFunction = displayFunctionName(
    state.showAllTrace ? (snap?.func || state.selectedFunction) : state.selectedFunction
  );
  const rangeIndex = buildFunctionRangeIndex();
  const focusRange = rangeIndex.get(normalizeFunctionName(targetFunction));
  if (!focusRange || focusRange.rangeStart === null || focusRange.rangeEnd === null) {
    return {
      entries: state.disasmLines,
      functionHeaders: buildAsmFunctionHeaders(state.disasmLines, rangeIndex)
    };
  }

  const focusEntries = state.disasmLines.filter((entry) => {
    const addr = parseAddress(entry?.addr);
    return addr !== null && addr >= focusRange.rangeStart && addr < focusRange.rangeEnd;
  });
  if (!focusEntries.length) {
    return {
      entries: state.disasmLines,
      functionHeaders: buildAsmFunctionHeaders(state.disasmLines, rangeIndex)
    };
  }

  const relatedRanges = [focusRange];
  const seenStarts = new Set([focusRange.rangeStart]);
  focusEntries.forEach((entry) => {
    const mnemonic = String(entry?.mnemonic || '').trim().toLowerCase();
    if (!mnemonic.startsWith('call')) return;
    const targetAddr = parseCallTargetAddress(entry);
    const calledRange = findFunctionRangeForAddress(rangeIndex, targetAddr);
    if (!calledRange?.name || calledRange.rangeStart === null) return;
    if (seenStarts.has(calledRange.rangeStart)) return;
    seenStarts.add(calledRange.rangeStart);
    relatedRanges.push(calledRange);
  });

  relatedRanges.sort((left, right) => (left.rangeStart ?? 0) - (right.rangeStart ?? 0));
  const relatedEntries = state.disasmLines.filter((entry) => {
    const addr = parseAddress(entry?.addr);
    if (addr === null) return false;
    return relatedRanges.some((range) => (
      range.rangeStart !== null
      && addr >= range.rangeStart
      && (range.rangeEnd === null || addr < range.rangeEnd)
    ));
  });

  const entries = relatedEntries.length ? relatedEntries : focusEntries;
  return {
    entries,
    functionHeaders: buildAsmFunctionHeaders(entries, rangeIndex)
  };
}

function buildCallSiteHints() {
  const hints = {};
  state.snapshots.forEach((snap) => {
    const addr = parseAddress(snap?.rip ?? snap?.eip);
    const symbol = displayFunctionName(snap?.effects?.external_symbol || '');
    if (addr !== null && symbol) {
      hints[`0x${addr.toString(16)}`] = symbol;
    }
  });
  return hints;
}

function buildCallTargetHints() {
  const hints = {};
  const rangeIndex = buildFunctionRangeIndex();
  rangeIndex.forEach((entry) => {
    if (entry.rangeStart !== null && entry.name) {
      hints[`0x${entry.rangeStart.toString(16)}`] = displayFunctionName(entry.name);
    }
  });
  return hints;
}

function updateControlsState() {
  const visibleCount = state.visibleSteps.length || state.snapshots.length || 1;
  const visibleIndex = findVisibleIndexForStep(state.currentStep);
  const canFilterTrace = !state.simStackMode
    && Boolean(state.selectedFunction)
    && state.snapshots.some((snap) => !sameFunction(snap?.func, state.selectedFunction));
  const canInspectFrame = !state.simStackMode && Boolean(state.selectedFunction);
  if (dom.stepRange) {
    dom.stepRange.min = 1;
    dom.stepRange.max = visibleCount;
    dom.stepRange.value = clampVisibleIndex(visibleIndex);
  }
  if (dom.stepLabel) {
    dom.stepLabel.textContent = `${clampVisibleIndex(visibleIndex)}/${visibleCount}`;
  }
  if (dom.showAllTrace) {
    dom.showAllTrace.checked = state.showAllTrace;
    dom.showAllTrace.disabled = !canFilterTrace;
    const toggle = dom.showAllTrace.closest('.toggle');
    if (toggle) toggle.classList.toggle('is-disabled', dom.showAllTrace.disabled);
  }
  if (dom.focusLabel) {
    dom.focusLabel.textContent = state.selectedFunction
      ? `Fonction: ${displayFunctionName(state.selectedFunction)}`
      : 'Fonction: a choisir';
    dom.focusLabel.style.display = state.simStackMode ? 'none' : '';
  }
  if (dom.stackModeFrame) {
    const isSimple = state.stackPanelMode === 'simple';
    dom.stackModeFrame.disabled = !canInspectFrame;
    dom.stackModeFrame.classList.toggle('is-active', isSimple);
    dom.stackModeFrame.setAttribute('aria-pressed', isSimple ? 'true' : 'false');
  }
  if (dom.stackModeAdvanced) {
    const isAdvanced = state.stackViewMode === 'advanced';
    dom.stackModeAdvanced.disabled = !canInspectFrame;
    dom.stackModeAdvanced.classList.toggle('is-active', isAdvanced);
    dom.stackModeAdvanced.setAttribute('aria-pressed', isAdvanced ? 'true' : 'false');
  }
  if (dom.stackModeExpert) {
    const isExpert = state.stackPanelMode === 'expert';
    dom.stackModeExpert.classList.toggle('is-active', isExpert);
    dom.stackModeExpert.setAttribute('aria-pressed', isExpert ? 'true' : 'false');
  }
}

function buildStatusText() {
  const visibleIndex = findVisibleIndexForStep(state.currentStep);
  const visibleCount = state.visibleSteps.length || state.snapshots.length || 1;
  const rawIndex = state.currentStep;
  const rawCount = state.snapshots.length;
  const focusName = displayFunctionName(state.selectedFunction);
  const sourceEnrichment = state.meta?.source_enrichment && typeof state.meta.source_enrichment === 'object'
    ? state.meta.source_enrichment
    : null;
  const sourceHint = sourceEnrichment?.enabled
    ? (sourceEnrichment.status === 'partial' ? ' • source C partiel' : ' • source C')
    : '';

  if (state.simStackMode) {
    return `Etape ${rawIndex}/${rawCount}${sourceHint}`;
  }

  if (!focusName || visibleCount === rawCount) {
    return `Trace complete ${rawIndex}/${rawCount}${sourceHint}`;
  }

  if (state.showAllTrace) {
    return `Trace complete ${rawIndex}/${rawCount} • focus ${focusName} ${visibleIndex}/${visibleCount}${sourceHint}`;
  }

  return `${focusName} • etape ${visibleIndex}/${visibleCount} • trace complete ${rawIndex}/${rawCount}${sourceHint}`;
}

function requestCurrentStepAnalysis() {
  const stepKey = String(state.currentStep);
  const hasAnalysis = Boolean(state.analysisByStep[stepKey]);
  const hasMcp = Boolean(state.mcp?.byStep?.[stepKey]);
  if (state.simStackMode || (hasAnalysis && hasMcp) || state.lastRequestedAnalysisStep === stepKey) {
    return;
  }
  state.lastRequestedAnalysisStep = stepKey;
  vscode.postMessage({
    type: 'requestAnalysis',
    traceRunId: state.traceRunId,
    step: state.currentStep
  });
}

function clearTraceState(statusText = 'No trace loaded') {
  state.traceRunId = null;
  state.currentTraceId = null;
  state.snapshots = [];
  state.risks = [];
  state.diagnostics = [];
  state.crash = null;
  state.meta = {};
  state.binaryMetadata = null;
  state.disasmLines = [];
  state.disasmFileText = '';
  state.disasmFileLines = [];
  state.disasmFilePath = null;
  state.memoryMap = null;
  state.analysis = null;
  state.analysisByStep = {};
  state.enrichment = { byStep: {} };
  state.mcp = {
    model: null,
    analysis: null,
    explanation: null,
    byStep: {}
  };
  state.lastRequestedAnalysisStep = null;
  state.currentStep = 1;
  state.visibleSteps = [];
  state.showAllTrace = false;
  state.selectedFunction = '';
  state.selectedStackSlotKey = null;
  state.lastHighlightedLine = null;
  state.lastDisasmLine = null;
  state.simStackMode = false;
  state.stackWorkspace = null;
  applyModeClass();
  updateControlsState();
  renderRuntimeEmptyState({ state, dom, statusText });
  renderRuntimeDisasmEmpty();
  clearTraceDebugInspector({ noTraceText: statusText });
}

function setStackViewMode(mode, options = {}) {
  const nextMode = normalizeStackViewMode(mode);
  const { rerender = true } = options;
  if (state.stackViewMode === nextMode && !rerender) return;
  state.stackViewMode = nextMode;
  persistStackViewMode(nextMode);
  updateControlsState();
  if (rerender && state.snapshots.length) {
    updateUI({ requestAnalysis: false });
  }
}

function setStackPanelMode(mode, options = {}) {
  const nextMode = normalizeStackPanelMode(mode);
  const { rerender = true } = options;
  if (state.stackPanelMode === nextMode && !rerender) return;
  state.stackPanelMode = nextMode;
  persistStackPanelMode(nextMode);
  updateControlsState();
  if (rerender && state.snapshots.length) {
    updateUI({ requestAnalysis: false });
  }
}

function setSelectedFunction(name, options = {}) {
  const { rerender = true } = options;
  const nextFunction = displayFunctionName(name || '');
  if (!nextFunction) return;
  const targetStep = findNearestStepForFunction(nextFunction, state.currentStep);
  state.selectedFunction = nextFunction;
  state.showAllTrace = false;
  rebuildVisibleSteps();
  if (targetStep !== null) {
    state.currentStep = targetStep;
  }
  ensureCurrentStepVisible();
  state.selectedStackSlotKey = null;
  if (rerender && state.snapshots.length) {
    updateUI();
  }
}

function clearSelectedFunction(options = {}) {
  const { rerender = true } = options;
  state.selectedFunction = '';
  state.showAllTrace = false;
  state.selectedStackSlotKey = null;
  rebuildVisibleSteps();
  ensureCurrentStepVisible();
  if (rerender && state.snapshots.length) {
    updateUI({ requestAnalysis: false });
  }
}

function setSelectedStackSlotKey(key, options = {}) {
  const { rerender = true } = options;
  state.selectedStackSlotKey = key ? String(key) : null;
  if (rerender && state.snapshots.length) {
    updateUI({ requestAnalysis: false });
  }
}

window.addEventListener('message', (event) => {
  const msg = event.data;
  if (!msg || !msg.type) return;

  if (msg.type === 'clearTrace' || msg.type === 'noTrace' || msg.type === 'dynamicTraceCleared') {
    clearTraceState('No trace loaded');
    return;
  }

  if (msg.type === 'disasmFileContent') {
    const expectedPath = state.meta?.disasm_path ? String(state.meta.disasm_path) : '';
    const messagePath = typeof msg.path === 'string' ? msg.path : '';
    if (expectedPath && messagePath && !pathsEquivalent(expectedPath, messagePath)) {
      return;
    }

    const content = typeof msg.content === 'string' ? msg.content : '';
    state.disasmFilePath = messagePath || expectedPath || null;
    state.disasmFileText = content;
    state.disasmFileLines = content ? content.split(/\r?\n/) : [];

    if (state.snapshots.length) {
      updateUI();
    } else {
      renderRuntimeDisasmEmpty();
    }
    return;
  }

  if (msg.type === 'analysisUpdate') {
    const messageTraceRunId = msg.traceRunId === undefined || msg.traceRunId === null
      ? null
      : String(msg.traceRunId);
    const currentTraceRunId = state.traceRunId === undefined || state.traceRunId === null
      ? null
      : String(state.traceRunId);
    if (messageTraceRunId && currentTraceRunId && messageTraceRunId !== currentTraceRunId) {
      return;
    }
    const step = Number(msg.step);
    if (!Number.isFinite(step) || step < 1) return;
    state.analysisByStep[String(step)] = msg.analysis ?? null;
    if (step === state.currentStep) {
      state.analysis = state.analysisByStep[String(step)] ?? null;
      updateUI({ requestAnalysis: false });
    }
    return;
  }

  if (msg.type === 'mcpUpdate') {
    const messageTraceRunId = msg.traceRunId === undefined || msg.traceRunId === null
      ? null
      : String(msg.traceRunId);
    const currentTraceRunId = state.traceRunId === undefined || state.traceRunId === null
      ? null
      : String(state.traceRunId);
    if (messageTraceRunId && currentTraceRunId && messageTraceRunId !== currentTraceRunId) {
      return;
    }
    const step = Number(msg.stepIndex ?? msg.step);
    if (!Number.isFinite(step) || step < 1) return;
    const payload = {
      model: msg.modelSummary ?? state.mcp.model ?? null,
      analysis: msg.instructionAnalysis ?? null,
      explanation: msg.explanation ?? null
    };
    state.mcp.model = payload.model;
    state.mcp.byStep[String(step)] = payload;
    if (step === state.currentStep) {
      state.mcp.analysis = payload.analysis;
      state.mcp.explanation = payload.explanation;
      updateUI({ requestAnalysis: false });
    }
    return;
  }

  if (msg.type === 'init') {
    const traceId = resolveTraceId(msg);
    const previousTraceId = state.currentTraceId;
    state.traceRunId = msg.traceRunId === undefined || msg.traceRunId === null
      ? (msg.meta?.trace_run_id === undefined || msg.meta?.trace_run_id === null
        ? null
        : String(msg.meta.trace_run_id))
      : String(msg.traceRunId);
    state.currentTraceId = traceId;
    state.snapshots = Array.isArray(msg.snapshots) ? msg.snapshots : [];
    state.risks = Array.isArray(msg.risks) ? msg.risks : [];
    state.diagnostics = Array.isArray(msg.diagnostics) ? msg.diagnostics : [];
    state.crash = msg.crash && typeof msg.crash === 'object' ? msg.crash : null;
    state.meta = msg.meta && typeof msg.meta === 'object' ? msg.meta : {};
    state.binaryMetadata = msg.binaryMetadata && typeof msg.binaryMetadata === 'object'
      ? msg.binaryMetadata
      : (state.meta.binary_metadata && typeof state.meta.binary_metadata === 'object'
        ? state.meta.binary_metadata
        : null);
    state.disasmLines = Array.isArray(state.meta.disasm) ? state.meta.disasm : [];
    state.disasmFileText = '';
    state.disasmFileLines = [];
    state.disasmFilePath = null;
    state.analysis = null;
    state.analysisByStep = msg.analysisByStep && typeof msg.analysisByStep === 'object'
      ? msg.analysisByStep
      : {};
    state.enrichment = msg.enrichment && typeof msg.enrichment === 'object'
      ? {
          ...msg.enrichment,
          byStep: msg.enrichment.byStep && typeof msg.enrichment.byStep === 'object'
            ? msg.enrichment.byStep
            : {}
        }
      : { byStep: {} };
    state.mcp = {
      model: null,
      analysis: null,
      explanation: null,
      byStep: {}
    };
    state.lastRequestedAnalysisStep = null;
    state.showAllTrace = false;
    state.stackViewMode = restoreStackViewMode();
    state.stackPanelMode = 'simple';
    state.selectedStackSlotKey = null;
    state.simStackMode = state.meta.view_mode === 'static';
    state.selectedFunction = '';
    state.stackWorkspace = null;
    applyModeClass();
    rebuildVisibleSteps();

    if (state.meta.disasm_path) {
      vscode.postMessage({
        type: 'readTextFile',
        path: state.meta.disasm_path
      });
    }

    if (!state.snapshots.length) {
      updateControlsState();
      renderRuntimeEmptyState({
        state,
        dom,
        statusText: 'Aucun snapshot a afficher (output.json vide).'
      });
      return;
    }

    state.currentStep = chooseInitStepForTrace({
      storage: localStorage,
      incomingTraceId: state.currentTraceId,
      currentTraceId: previousTraceId,
      previousTraceIdKey: PREVIOUS_TRACE_ID_STORAGE_KEY,
      stepStoreKey: STEP_STORAGE_KEY,
      snapshotCount: state.snapshots.length
    });
    ensureCurrentStepVisible();
    updateUI();
  }
});

function updateUI(options = {}) {
  const { requestAnalysis = true } = options;

  if (!state.snapshots.length) {
    renderRuntimeEmptyState({ state, dom });
    return;
  }

  rebuildVisibleSteps();
  ensureCurrentStepVisible();
  updateControlsState();

  const snap = state.snapshots[state.currentStep - 1];
  if (!snap) return;

  persistViewedStep({
    storage: localStorage,
    traceId: state.currentTraceId,
    previousTraceIdKey: PREVIOUS_TRACE_ID_STORAGE_KEY,
    stepStoreKey: STEP_STORAGE_KEY,
    step: state.currentStep
  });

  const line = typeof snap.line === 'number' ? snap.line : null;
  const statusText = buildStatusText();

  const stackItems = Array.isArray(snap.stack) ? snap.stack : [];
  const registerItems = Array.isArray(snap.registers)
    ? snap.registers
    : Array.isArray(snap.regs)
    ? snap.regs
    : [];
  const prevSnap = state.currentStep > 1 ? state.snapshots[state.currentStep - 2] : null;
  const prevRegisterItems = Array.isArray(prevSnap?.registers)
    ? prevSnap.registers
    : Array.isArray(prevSnap?.regs)
    ? prevSnap.regs
    : [];
  const regMap = buildRegisterMap(registerItems);
  const prevRegMap = buildRegisterMap(prevRegisterItems);
  const currentAddr = snap.rip ?? snap.eip ?? null;
  const expectedFunction = displayFunctionName(
    state.showAllTrace ? snap.func : (state.selectedFunction || snap.func)
  );
  const analysis = getScopedAnalysisForStep(state.currentStep, snap, expectedFunction);
  const mcp = getScopedMcpForStep(state.currentStep, snap, expectedFunction);
  const stepEnrichment = getEnrichmentForStep(state.currentStep);
  const currentCrash = state.crash && Number(state.crash.step) === Number(state.currentStep)
    ? state.crash
    : null;
  const topLevelDiagnostics = diagnosticsForStep(state.diagnostics, state.currentStep);
  const currentDiagnostics = mergeCrashDiagnostic(
    topLevelDiagnostics.length
      ? topLevelDiagnostics
      : (Array.isArray(analysis?.diagnostics) ? analysis.diagnostics : []),
    currentCrash,
    state.currentStep
  );
  const crashDiagnostics = persistentCrashDiagnostics(state.crash, state.diagnostics);
  state.analysis = analysis;
  state.mcp.analysis = mcp?.analysis ?? null;
  state.mcp.explanation = mcp?.explanation ?? null;
  if (mcp?.model) state.mcp.model = mcp.model;

  const activeDisasmLine = resolveActiveDisasmFileLine(state.disasmLines, toDisasmAddress(currentAddr));
  const disasmRender = buildDisasmEntriesForRender();
  const callSiteHints = buildCallSiteHints();
  const callTargetHints = buildCallTargetHints();

  applyModeClass();
  const renderResult = renderRuntimeSnapshot({
    state,
    dom,
    snap,
    prevSnap,
    line,
    stackItems,
    registerItems,
    regMap,
    prevRegMap,
    analysis,
    mcp,
    stepEnrichment,
    currentDiagnostics,
    currentCrash,
    activeDisasmLine,
    disasmRender,
    callSiteHints,
    callTargetHints,
    crashDiagnostics,
    statusText,
    displayFunctionName,
    onSelectFunction: (functionName) => {
      setSelectedFunction(functionName);
    },
    onClearSelectedFunction: () => {
      clearSelectedFunction();
    },
    onSelectSlotKey: (key) => {
      const nextKey = state.selectedStackSlotKey === key ? null : key;
      setSelectedStackSlotKey(nextKey);
    },
    onJumpToStep: (step) => {
      jumpToTraceStep(step);
    },
    resolveCodeJumpTarget: (value) => resolveDisasmJumpTarget(state.disasmLines, value),
    onCodeAddressClick: (target) => {
      if (target?.lineNumber) {
        scrollDisasmToFileLine(target.lineNumber);
      }
    }
  });
  state.stackWorkspace = renderResult.stackWorkspace ?? null;
  renderTraceDebugInspector({
    debugSnapshot: buildTraceDebugSnapshot({
      state,
      snap,
      analysis,
      mcp,
      stackWorkspace: state.stackWorkspace,
      currentStep: state.currentStep,
      displayFunctionName
    })
  });
  if ((renderResult.selectedSlotKey || null) !== (state.selectedStackSlotKey || null)) {
    state.selectedStackSlotKey = renderResult.selectedSlotKey || null;
  }

  if (!state.simStackMode && requestAnalysis) {
    requestCurrentStepAnalysis();
  }

  if (state.simStackMode && line !== null) {
    if (state.lastHighlightedLine !== line) {
      state.lastHighlightedLine = line;
      vscode.postMessage({
        type: 'goToLine',
        line,
        file: state.meta.asm_path
      });
    }
  }
}

dom.btnPrev.addEventListener('click', () => {
  setStepFromVisibleIndex(findVisibleIndexForStep(state.currentStep) - 1);
  updateUI();
});

dom.btnNext.addEventListener('click', () => {
  setStepFromVisibleIndex(findVisibleIndexForStep(state.currentStep) + 1);
  updateUI();
});

dom.stepRange.addEventListener('input', () => {
  const visibleIndex = parseInt(dom.stepRange.value, 10);
  setStepFromVisibleIndex(visibleIndex);
  updateUI();
});

if (dom.showAllTrace) {
  dom.showAllTrace.addEventListener('change', () => {
    state.showAllTrace = Boolean(dom.showAllTrace.checked);
    rebuildVisibleSteps();
    ensureCurrentStepVisible();
    updateUI();
  });
}

if (dom.stackModeFrame) {
  dom.stackModeFrame.addEventListener('click', () => {
    setStackViewMode('frame', { rerender: false });
    setStackPanelMode('simple');
  });
}

if (dom.stackModeAdvanced) {
  dom.stackModeAdvanced.addEventListener('click', () => {
    setStackViewMode('advanced');
  });
}

// Hub integration — expose loadTrace for runtimeSessionController
if (window.POFHubMessageBus) {
  window.POFHubRuntime = {
    loadTrace(data) {
      window.dispatchEvent(new MessageEvent('message', {
        data: {
          type: 'init',
          traceRunId: data.traceRunId ?? null,
          snapshots: data.snapshots ?? [],
          risks: data.risks ?? [],
          diagnostics: data.diagnostics ?? [],
          crash: data.crash ?? null,
          meta: data.meta ?? {},
          binaryMetadata: data.binaryMetadata ?? data.meta?.binary_metadata ?? null,
          analysisByStep: data.analysisByStep ?? {},
          enrichment: data.enrichment ?? {},
        }
      }));
    },
    clearTrace() {
      window.dispatchEvent(new MessageEvent('message', {
        data: {
          type: 'clearTrace'
        }
      }));
    }
  };
}
