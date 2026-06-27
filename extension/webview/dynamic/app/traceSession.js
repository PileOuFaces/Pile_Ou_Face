/**
 * @file traceSession.js
 * @brief Helpers purs pour identifier une trace et restaurer son etape UI.
 */

function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function hashText(text) {
  let hash = 2166136261;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16);
}

export function resolveTraceId(message) {
  const explicit = message?.meta?.trace_run_id ?? message?.traceRunId ?? message?.runId ?? message?.meta?.run_id;
  if (explicit !== undefined && explicit !== null && String(explicit).trim()) {
    return `run:${String(explicit).trim()}`;
  }

  const meta = message?.meta && typeof message.meta === 'object' ? message.meta : {};
  const snapshots = Array.isArray(message?.snapshots) ? message.snapshots : [];
  const crash = message?.crash && typeof message.crash === 'object' ? message.crash : null;
  const fingerprint = stableStringify({
    path: meta.trace_path || meta.output_path || meta.json_path || meta.disasm_path || '',
    count: snapshots.length,
    first: snapshots[0] || null,
    last: snapshots[snapshots.length - 1] || null,
    crash
  });
  return `trace:${hashText(fingerprint)}`;
}

export function readStepStore(storage, key) {
  try {
    const raw = storage?.getItem(key);
    const parsed = raw ? JSON.parse(raw) : {};
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (_) {
    return {};
  }
}

export function chooseInitialStep({
  storage,
  traceId,
  previousTraceIdKey,
  stepStoreKey,
  snapshotCount
}) {
  const count = Number(snapshotCount);
  if (!Number.isFinite(count) || count < 1) return 1;

  let previousTraceId = null;
  try {
    previousTraceId = storage?.getItem(previousTraceIdKey) || null;
  } catch (_) {
    previousTraceId = null;
  }

  if (previousTraceId !== traceId) return 1;

  const stepStore = readStepStore(storage, stepStoreKey);
  const saved = Number.parseInt(stepStore[traceId], 10);
  return Number.isFinite(saved) && saved >= 1 && saved <= count ? saved : 1;
}

export function persistViewedStep({
  storage,
  traceId,
  previousTraceIdKey,
  stepStoreKey,
  step
}) {
  if (!traceId) return;
  try {
    const stepStore = readStepStore(storage, stepStoreKey);
    stepStore[traceId] = String(Math.max(1, Math.trunc(Number(step) || 1)));
    storage?.setItem(stepStoreKey, JSON.stringify(stepStore));
    storage?.setItem(previousTraceIdKey, traceId);
  } catch (_) {
    /* ignore */
  }
}

export function clearSavedStep({
  storage,
  traceId,
  stepStoreKey
}) {
  if (!traceId) return;
  try {
    const stepStore = readStepStore(storage, stepStoreKey);
    delete stepStore[traceId];
    storage?.setItem(stepStoreKey, JSON.stringify(stepStore));
  } catch (_) {
    /* ignore */
  }
}

export function chooseInitStepForTrace({
  storage,
  incomingTraceId,
  currentTraceId,
  previousTraceIdKey,
  stepStoreKey,
  snapshotCount
}) {
  if (currentTraceId && currentTraceId !== incomingTraceId) {
    clearSavedStep({
      storage,
      traceId: incomingTraceId,
      stepStoreKey
    });
    return 1;
  }

  return chooseInitialStep({
    storage,
    traceId: incomingTraceId,
    previousTraceIdKey,
    stepStoreKey,
    snapshotCount
  });
}
