/**
 * Classic-script controller for hub-side dynamic visualizer orchestration.
 * The actual visualizer state machine remains in the standalone dynamic app.
 */
(function initHubDynamicVisualizerController(global) {
  function initDynamicVisualizerController(deps) {
    const {
      postMessage,
      setDynamicTraceStatus,
    } = deps || {};

    let currentTracePath = '';
    let currentTraceRunId = null;

    function normalizeTracePath(traceOrPath) {
      if (typeof traceOrPath === 'string') return String(traceOrPath || '').trim();
      if (!traceOrPath || typeof traceOrPath !== 'object') return '';
      return String(
        traceOrPath.path
        || traceOrPath.tracePath
        || traceOrPath.meta?.trace_path
        || traceOrPath.meta?.output_path
        || ''
      ).trim();
    }

    function resolveTraceRunId(traceOrPath) {
      if (!traceOrPath || typeof traceOrPath !== 'object') return null;
      const raw = traceOrPath.runId ?? traceOrPath.traceRunId ?? traceOrPath.meta?.trace_run_id ?? null;
      if (raw === undefined || raw === null || String(raw).trim() === '') return null;
      return String(raw).trim();
    }

    function safePostMessage(message) {
      if (typeof postMessage === 'function') postMessage(message);
    }

    function resetStepForNewRun(traceRunId) {
      currentTraceRunId = traceRunId === undefined || traceRunId === null || String(traceRunId).trim() === ''
        ? null
        : String(traceRunId).trim();
      return 1;
    }

    function restoreStepForTrace(traceRunId) {
      if (traceRunId === undefined || traceRunId === null || String(traceRunId).trim() === '') {
        return null;
      }
      currentTraceRunId = String(traceRunId).trim();
      return null;
    }

    function openVisualizer(traceOrPath, options = {}) {
      const tracePath = normalizeTracePath(traceOrPath);
      const runId = resolveTraceRunId(traceOrPath);
      const runLabel = String(options.runLabel || '').trim();
      if (!tracePath) return false;
      currentTracePath = tracePath;
      if (runId) restoreStepForTrace(runId);
      if (typeof setDynamicTraceStatus === 'function') {
        setDynamicTraceStatus(runLabel ? `Ouverture de la trace ${runLabel}...` : 'Ouverture de la trace...');
      }
      safePostMessage({ type: 'openDynamicTraceHistory', tracePath });
      return true;
    }

    function handleVisualizerMessage(message) {
      if (!message || typeof message !== 'object') return false;

      if (message.type === 'dynamicTraceHistory') {
        const activePath = String(message.activeTracePath || '').trim();
        if (activePath) currentTracePath = activePath;
        const items = Array.isArray(message.items) ? message.items : [];
        const activeItem = items.find((item) => item?.active) || items.find((item) => String(item?.path || '').trim() === activePath) || null;
        if (activeItem?.runId !== undefined && activeItem?.runId !== null && String(activeItem.runId).trim() !== '') {
          currentTraceRunId = String(activeItem.runId).trim();
        }
        return false;
      }

      if (message.type === 'dynamicTraceCleared' || message.type === 'clearTrace' || message.type === 'noTrace') {
        currentTracePath = '';
        currentTraceRunId = null;
        return false;
      }

      if (message.type === 'runTraceDone') {
        return false;
      }

      return false;
    }

    return {
      openVisualizer,
      handleVisualizerMessage,
      resetStepForNewRun,
      restoreStepForTrace,
    };
  }

  const api = { initDynamicVisualizerController };
  global.POFHubDynamicVisualizerController = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.dynamicVisualizerController = api;
  }
})(window);
