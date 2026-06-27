/**
 * @file debugTraceInspector.js
 * @brief Lightweight Dynamic trace JSON inspector for debugging visualizer bugs.
 */

const INSPECTOR_ROOT_ID = 'traceDebugInspector';
const INSPECTOR_BODY_ID = 'traceDebugBody';
const INSPECTOR_TOGGLE_ID = 'traceDebugToggle';
const INSPECTOR_COPY_ID = 'traceDebugCopy';

export function isTraceDebugInspectorEnabled() {
  return globalThis.__POF_TRACE_DEBUG_INSPECTOR === true;
}

function clean(value) {
  return String(value ?? '').trim();
}

function safeJson(value, space = 2) {
  try {
    return JSON.stringify(value ?? null, null, space);
  } catch (error) {
    return JSON.stringify({ error: String(error?.message || error || 'JSON stringify failed') }, null, space);
  }
}

function snapshotAddress(snapshot) {
  return clean(snapshot?.rip ?? snapshot?.eip ?? snapshot?.ip ?? snapshot?.instruction?.address);
}

function modelNameFromMcp(mcp) {
  return clean(mcp?.model?.name || mcp?.model?.functionName || mcp?.analysis?.function?.name);
}

function renderedItemIds(stackWorkspace) {
  const entries = Array.isArray(stackWorkspace?.frameModel?.entries)
    ? stackWorkspace.frameModel.entries
    : [];
  return entries
    .map((entry) => clean(entry?.id || entry?.key))
    .filter(Boolean);
}

function normalizeFunctionName(value) {
  return clean(value)
    .replace(/[<>]/g, '')
    .replace(/@.*/, '')
    .replace(/\([^)]*\)\s*$/, '')
    .replace(/^sym\./, '')
    .trim()
    .toLowerCase();
}

function sameFunctionName(left, right) {
  const lhs = normalizeFunctionName(left);
  const rhs = normalizeFunctionName(right);
  return Boolean(lhs && rhs && lhs === rhs);
}

function formatFunctionCall(name) {
  const value = clean(name);
  return value ? `${value}()` : 'selected function';
}

function findFirstStepForFunction(snapshots, functionName) {
  if (!functionName || !Array.isArray(snapshots)) return null;
  const index = snapshots.findIndex((snapshot) => sameFunctionName(snapshot?.func, functionName));
  return index >= 0 ? index + 1 : null;
}

export function buildTraceDebugSnapshot({
  state,
  snap,
  analysis,
  mcp,
  stackWorkspace,
  currentStep,
  displayFunctionName = (value) => clean(value)
} = {}) {
  const safeState = state && typeof state === 'object' ? state : {};
  const safeSnap = snap && typeof snap === 'object' ? snap : null;
  const safeAnalysis = analysis && typeof analysis === 'object' ? analysis : null;
  const selectedStep = Number(currentStep || safeState.currentStep || 0) || 0;
  const activeFunction = clean(safeState.selectedFunction || safeSnap?.func || safeAnalysis?.function?.name);
  const currentFunction = clean(displayFunctionName(safeSnap?.func || safeAnalysis?.function?.name || ''));
  const frameModel = stackWorkspace?.frameModel || null;
  const debug = frameModel?.debug || {};
  const itemIds = renderedItemIds(stackWorkspace);
  const meta = safeState.meta && typeof safeState.meta === 'object' ? safeState.meta : {};
  const binaryMetadata = safeState.binaryMetadata && typeof safeState.binaryMetadata === 'object'
    ? safeState.binaryMetadata
    : (meta.binary_metadata && typeof meta.binary_metadata === 'object' ? meta.binary_metadata : null);
  const firstStepForActiveFunction = debug.firstStepForActiveFunction !== null
    && debug.firstStepForActiveFunction !== undefined
    && Number.isFinite(Number(debug.firstStepForActiveFunction))
    ? Number(debug.firstStepForActiveFunction)
    : findFirstStepForFunction(safeState.snapshots, activeFunction);
  const mismatchExplanation = clean(debug.mismatchExplanation)
    || (activeFunction && currentFunction && !sameFunctionName(activeFunction, currentFunction)
      ? `${formatFunctionCall(activeFunction)} is selected, but the current trace step is still in ${formatFunctionCall(currentFunction)}.`
      : '');

  return {
    summary: {
      traceRunId: clean(safeState.traceRunId ?? meta.trace_run_id),
      activeFunction,
      currentFunction,
      selectedStep,
      instructionAddress: snapshotAddress(safeSnap),
      currentAddress: snapshotAddress(safeSnap),
      rawStackModelFunction: modelNameFromMcp(mcp),
      selectedFrameFunction: clean(frameModel?.functionName),
      resolvedFunction: clean(debug.resolvedFunction),
      rejectedFunction: clean(debug.rejectedFunction),
      rejectedReason: clean(debug.rejectedReason),
      firstStepForActiveFunction,
      mismatchExplanation,
      binaryMetadataAvailable: Boolean(binaryMetadata),
      renderedItemIds: itemIds,
      diagnostics: Array.isArray(safeState.diagnostics) ? safeState.diagnostics : []
    },
    snapshot: safeSnap,
    stackWorkspace: frameModel
      ? {
          functionName: clean(frameModel.functionName),
          emptyText: clean(frameModel.emptyText),
          debug: frameModel.debug || {},
          entries: (Array.isArray(frameModel.entries) ? frameModel.entries : []).map((entry) => ({
            id: clean(entry?.id || entry?.key),
            name: clean(entry?.name),
            kind: clean(entry?.kind),
            offset: entry?.offset,
            size: entry?.size
          }))
        }
      : null,
    traceMeta: meta,
    binaryMetadata,
    rawTrace: {
      traceRunId: clean(safeState.traceRunId ?? meta.trace_run_id),
      meta,
      snapshots: Array.isArray(safeState.snapshots) ? safeState.snapshots : [],
      risks: Array.isArray(safeState.risks) ? safeState.risks : [],
      diagnostics: Array.isArray(safeState.diagnostics) ? safeState.diagnostics : [],
      crash: safeState.crash || null,
      analysisByStep: safeState.analysisByStep || {},
      enrichment: safeState.enrichment || {}
    }
  };
}

export function getTraceDebugCopyJson(debugSnapshot) {
  return safeJson(debugSnapshot || {});
}

function getDocument(documentRef) {
  return documentRef || (typeof document !== 'undefined' ? document : null);
}

function findElement(doc, root, id) {
  if (doc && typeof doc.getElementById === 'function') {
    const found = doc.getElementById(id);
    if (found) return found;
  }
  if (root && typeof root.querySelector === 'function') {
    return root.querySelector(`#${id}`);
  }
  return null;
}

function ensureInspector(documentRef) {
  const doc = getDocument(documentRef);
  if (!doc) return null;
  let root = doc.getElementById(INSPECTOR_ROOT_ID);
  if (!root) {
    root = doc.createElement('section');
    root.id = INSPECTOR_ROOT_ID;
    root.className = 'trace-debug-inspector';
    root.hidden = true;
    const anchor = doc.querySelector('.container') || doc.body;
    if (anchor) anchor.appendChild(root);
  }

  let toggle = findElement(doc, root, INSPECTOR_TOGGLE_ID);
  let copy = findElement(doc, root, INSPECTOR_COPY_ID);
  let body = findElement(doc, root, INSPECTOR_BODY_ID);

  if (!toggle || !copy) {
    const header = doc.createElement('div');
    header.className = 'trace-debug-header';
    if (!toggle) {
      toggle = doc.createElement('button');
      toggle.id = INSPECTOR_TOGGLE_ID;
      toggle.type = 'button';
      toggle.className = 'btn btn-secondary btn-sm trace-debug-toggle';
      toggle.textContent = 'Debug JSON';
      header.appendChild(toggle);
    }
    if (!copy) {
      copy = doc.createElement('button');
      copy.id = INSPECTOR_COPY_ID;
      copy.type = 'button';
      copy.className = 'btn btn-secondary btn-sm trace-debug-copy';
      copy.hidden = true;
      copy.textContent = 'Copy JSON';
      header.appendChild(copy);
    }
    root.appendChild(header);
  }

  if (!body) {
    body = doc.createElement('div');
    body.id = INSPECTOR_BODY_ID;
    body.className = 'trace-debug-body';
    body.hidden = true;
    root.appendChild(body);
  }

  return { root, body, toggle, copy };
}

function writeText(text) {
  const clipboard = typeof navigator !== 'undefined' ? navigator.clipboard : null;
  if (clipboard && typeof clipboard.writeText === 'function') {
    return clipboard.writeText(text);
  }
  return Promise.resolve(false);
}

export function renderTraceDebugInspector({
  documentRef,
  debugSnapshot,
  noTraceText = 'No trace loaded',
  copyText = writeText
} = {}) {
  const doc = getDocument(documentRef);
  const inspector = ensureInspector(documentRef);
  if (!inspector) return null;
  const { root, body, toggle, copy } = inspector;

  if (!isTraceDebugInspectorEnabled()) {
    root.hidden = true;
    if (toggle) toggle.hidden = true;
    if (copy) copy.hidden = true;
    if (body) body.hidden = true;
    return root;
  }

  root.hidden = false;

  if (toggle) {
    toggle.hidden = false;
    toggle.textContent = 'Debug JSON';
    toggle.setAttribute?.('aria-controls', INSPECTOR_BODY_ID);
    toggle.setAttribute?.('aria-expanded', String(!body?.hidden));
    if (!toggle.__traceDebugBound) {
      toggle.__traceDebugBound = true;
      toggle.addEventListener('click', () => {
        if (!body) return;
        body.hidden = !body.hidden;
        toggle.setAttribute?.('aria-expanded', String(!body.hidden));
        toggle.classList?.toggle('is-active', !body.hidden);
      });
    }
  }

  const hasTrace = Boolean(debugSnapshot?.snapshot || debugSnapshot?.summary?.traceRunId);
  if (copy) copy.hidden = !hasTrace;
  if (!hasTrace) {
    if (body) {
      body.hidden = false;
      body.textContent = noTraceText;
    }
    if (toggle) {
      toggle.setAttribute?.('aria-expanded', 'true');
      toggle.classList?.add('is-active');
    }
    return root;
  }

  if (copy) {
    copy.onclick = () => copyText(getTraceDebugCopyJson(debugSnapshot));
  }

  if (body) {
    body.replaceChildren();
    const summary = doc.createElement('pre');
    summary.className = 'trace-debug-summary';
    summary.textContent = safeJson(debugSnapshot.summary);
    body.appendChild(summary);

    const snapshotDetails = doc.createElement('details');
    snapshotDetails.open = false;
    snapshotDetails.innerHTML = '<summary>Raw current snapshot</summary>';
    const snapshotPre = doc.createElement('pre');
    snapshotPre.textContent = safeJson(debugSnapshot.snapshot);
    snapshotDetails.appendChild(snapshotPre);
    body.appendChild(snapshotDetails);

    const stackDetails = doc.createElement('details');
    stackDetails.open = false;
    stackDetails.innerHTML = '<summary>Stack model input/output</summary>';
    const stackPre = doc.createElement('pre');
    stackPre.textContent = safeJson(debugSnapshot.stackWorkspace);
    stackDetails.appendChild(stackPre);
    body.appendChild(stackDetails);

    const traceDetails = doc.createElement('details');
    traceDetails.open = false;
    traceDetails.innerHTML = '<summary>Full raw trace</summary>';
    const tracePre = doc.createElement('pre');
    traceDetails.addEventListener('toggle', () => {
      if (traceDetails.open && !tracePre.__traceDebugLoaded) {
        tracePre.__traceDebugLoaded = true;
        tracePre.textContent = safeJson(debugSnapshot.rawTrace);
      }
    });
    traceDetails.appendChild(tracePre);
    body.appendChild(traceDetails);

    if (debugSnapshot.binaryMetadata) {
      const metadataDetails = doc.createElement('details');
      metadataDetails.open = false;
      metadataDetails.innerHTML = '<summary>Binary Metadata</summary>';
      const metadataPre = doc.createElement('pre');
      metadataPre.className = 'trace-debug-binary-metadata';
      metadataDetails.addEventListener('toggle', () => {
        if (metadataDetails.open && !metadataPre.__binaryMetadataLoaded) {
          metadataPre.__binaryMetadataLoaded = true;
          metadataPre.textContent = safeJson({
            Binary: debugSnapshot.binaryMetadata.binary || {},
            Sections: debugSnapshot.binaryMetadata.sections || [],
            Symbols: debugSnapshot.binaryMetadata.symbols || [],
            Functions: debugSnapshot.binaryMetadata.functions || [],
            "PLT/GOT": debugSnapshot.binaryMetadata.plt || [],
            Runtime: debugSnapshot.binaryMetadata.runtime || {},
            Diagnostics: debugSnapshot.binaryMetadata.diagnostics || []
          });
        }
      });
      metadataDetails.appendChild(metadataPre);
      body.appendChild(metadataDetails);
    }
  }

  return root;
}

export function clearTraceDebugInspector({ documentRef, noTraceText = 'No trace loaded' } = {}) {
  return renderTraceDebugInspector({ documentRef, debugSnapshot: null, noTraceText });
}
