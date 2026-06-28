/**
 * @file runtimeRenderPipeline.js
 * @brief Orchestration du rendu Runtime pour le snapshot courant.
 * @details Ne possede pas l'etat et ne gere ni navigation ni events.
 */
import { renderStack } from './stack.js';
import { renderMemoryDump, renderRegisters, renderRisks } from './render.js';
import { renderExplain } from './explain.js';
import { renderDisasmPanel, initDisasmContextMenu } from './disasmPanel.js';

export function renderRuntimeEmptyState({ state, dom, statusText = 'Aucune donnee.' }) {
  if (dom.status) dom.status.textContent = statusText;
  if (dom.stepLabel) dom.stepLabel.textContent = '0/0';
  renderStack([], {}, state.meta, {
    displayMode: state.stackViewMode,
    stackPanelMode: state.stackPanelMode,
    snapshots: state.snapshots,
    currentStep: state.currentStep,
    selectedFunction: state.selectedFunction,
    selectedSlotKey: state.selectedStackSlotKey
  });
  renderRegisters([]);
  renderRisks([], null);
  renderMemoryDump([], {}, state.meta, null);
  renderExplain(null, null, {}, {}, state.meta, null);
  renderDisasmPanel([], null, {});
  initDisasmContextMenu();
}

export function renderRuntimeDisasmEmpty() {
  renderDisasmPanel([], null, {});
}

function formatStepEnrichmentLabel(stepEnrichment) {
  if (!stepEnrichment || typeof stepEnrichment !== 'object') return '';
  const symbol = String(stepEnrichment.symbol || '').trim();
  const functionName = String(stepEnrichment.functionName || '').trim();
  const offset = Number(stepEnrichment.functionOffset);
  if (symbol && Number.isFinite(offset) && offset === 0) return symbol;
  if (functionName && Number.isFinite(offset)) {
    return offset === 0
      ? functionName
      : `${functionName}+0x${Math.abs(offset).toString(16)}`;
  }
  return symbol || functionName || String(stepEnrichment.rip || '').trim();
}

function confidenceValue(confidence) {
  if (typeof confidence === 'number' && Number.isFinite(confidence)) {
    return Math.max(0, Math.min(1, confidence));
  }
  const raw = String(confidence || '').trim().toLowerCase();
  if (raw === 'high') return 0.92;
  if (raw === 'medium') return 0.75;
  if (raw === 'low') return 0.55;
  return 0.82;
}

function localFromStackHint(hint) {
  if (!hint || typeof hint !== 'object') return null;
  const offset = Number(hint.offset);
  if (!Number.isFinite(offset)) return null;
  const kind = String(hint.kind || '').trim().toLowerCase() || 'local';
  return {
    name: String(hint.label || kind || 'buffer').trim(),
    role: kind,
    offset,
    size: Number.isFinite(Number(hint.size)) && Number(hint.size) > 0 ? Number(hint.size) : 1,
    cType: kind === 'buffer' ? 'char[]' : '',
    source: String(hint.source || 'static').trim() || 'static',
    confidence: confidenceValue(hint.confidence),
    evidence: [
      hint.call ? `destination passed to ${hint.call}` : '',
      hint.offsetLabel ? `off=${hint.offsetLabel}` : ''
    ].filter(Boolean)
  };
}

function mergeStepEnrichmentIntoMcp(mcp, stepEnrichment, modelName = '') {
  const stackHints = Array.isArray(stepEnrichment?.stackHints) ? stepEnrichment.stackHints : [];
  const hintLocals = stackHints.map(localFromStackHint).filter(Boolean);
  if (!hintLocals.length) return mcp;
  const baseMcp = mcp && typeof mcp === 'object' ? mcp : {};
  const baseModel = baseMcp.model && typeof baseMcp.model === 'object' ? baseMcp.model : {};
  const locals = Array.isArray(baseModel.locals) ? baseModel.locals : [];
  const resolvedModelName = baseModel.name
    || modelName
    || stepEnrichment?.functionName
    || stackHints.find((hint) => hint?.function)?.function
    || '';
  return {
    ...baseMcp,
    model: {
      ...baseModel,
      name: resolvedModelName,
      locals: [...locals, ...hintLocals]
    }
  };
}

export function renderRuntimeSnapshot({
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
  onSelectFunction,
  onClearSelectedFunction,
  onSelectSlotKey,
  onJumpToStep,
  resolveCodeJumpTarget,
  onCodeAddressClick
}) {
  if (dom.status) dom.status.textContent = statusText;

  if (dom.explainSubtitle) {
    dom.explainSubtitle.textContent = snap.func
      ? `${displayFunctionName(snap.func)} • ligne ${line ?? '?'}`
      : `Ligne ${line ?? '?'}`;
  }

  const functionName = state.showAllTrace && snap.func
    ? displayFunctionName(snap.func)
    : displayFunctionName(state.selectedFunction || snap.func);

  if (dom.disasmSubtitle) {
    const enrichedLabel = formatStepEnrichmentLabel(stepEnrichment);
    dom.disasmSubtitle.textContent = enrichedLabel || (functionName ? `${functionName}()` : 'Fonction active');
  }

  const stackMcp = mergeStepEnrichmentIntoMcp(mcp, stepEnrichment, functionName);
  const stackWorkspace = renderStack(stackItems, regMap, state.meta, {
    abstractMode: state.simStackMode,
    displayMode: state.stackViewMode,
    stackPanelMode: state.stackPanelMode,
    analysis,
    diagnostics: currentDiagnostics,
    mcp: stackMcp,
    snapshot: snap,
    snapshots: state.snapshots,
    currentStep: state.currentStep,
    selectedFunction: state.selectedFunction,
    selectedSlotKey: state.selectedStackSlotKey,
    memoryMap: state.memoryMap,
    debugMemory: state.debugMemory,
    payloadText: state.meta?.payload_text || state.meta?.argv1 || '',
    payloadHex: state.meta?.payload_hex || state.meta?.input?.previewHex || '',
    onSelectFunction,
    onClearSelectedFunction,
    onSelectSlotKey,
    onJumpToStep,
    resolveCodeJumpTarget,
    onCodeAddressClick
  });

  renderRegisters(registerItems, currentDiagnostics);
  renderRisks(state.risks, line);
  renderMemoryDump(state.simStackMode ? [] : stackItems, regMap, state.meta, snap);
  renderExplain(snap, prevSnap, regMap, prevRegMap, state.meta, analysis, mcp, currentDiagnostics, currentCrash);
  renderDisasmPanel(disasmRender.entries, activeDisasmLine, {
    functionName,
    functionHeaders: disasmRender.functionHeaders,
    callSiteHints,
    callTargetHints,
    diagnostics: currentDiagnostics,
    crashDiagnostics
  });

  return {
    stackWorkspace: stackWorkspace ?? null,
    selectedSlotKey: stackWorkspace?.selectedSlotKey || null
  };
}
