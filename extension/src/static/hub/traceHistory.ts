// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck

function createTraceHistory({
  panel,
  root,
  storageDir,
  ensureTempDir,
  readTraceJson,
  writeTraceJson,
  setViewMode,
  buildSourceEnrichmentMeta,
  attachTraceAddressEnrichment,
  payloadTargetLabel,
  normalizePayloadTargetMode,
  openVisualizerWebview,
  vscode,
  fs,
  path,
  crypto,
}) {
  let _activeDynamicTracePath = '';
  const getActiveDynamicTracePath = () => _activeDynamicTracePath;
  const setActiveDynamicTracePath = (p) => { _activeDynamicTracePath = p; };

  const buildTraceRunArtifacts = (tempDir, runId) => {
    const nonce = crypto.randomBytes(6).toString('hex');
    const stem = `output.run-${runId}-${nonce}`;
    return {
      canonicalJsonPath: path.resolve(tempDir, 'output.json'),
      isolatedJsonPath: path.resolve(tempDir, `${stem}.json`)
    };
  };

  const normalizeHistoryPath = (targetPath) => path.normalize(String(targetPath || ''));

  const deriveTraceRunIdFromPath = (targetPath) => {
    const match = path.basename(String(targetPath || '')).match(/^output\.run-(\d+)-/);
    return match ? Number(match[1]) : null;
  };

  const ensureTraceDisasmPath = (trace, jsonPath) => {
    if (!trace || typeof trace !== 'object') return trace;
    trace.meta = trace.meta && typeof trace.meta === 'object' ? trace.meta : {};
    if (trace.meta.disasm_path) return trace;
    if (String(jsonPath || '').endsWith('.json')) {
      const candidate = String(jsonPath).slice(0, -5) + '.disasm.asm';
      if (fs.existsSync(candidate)) trace.meta.disasm_path = candidate;
    }
    return trace;
  };

  const enrichTraceForVisualizer = (trace, {
    jsonPath = '',
    traceRunId = null,
    sourcePath = '',
    archBits = 64,
    viewMode = 'dynamic',
    symbols = []
  } = {}) => {
    if (!trace || typeof trace !== 'object') return trace;
    trace.meta = trace.meta && typeof trace.meta === 'object' ? trace.meta : {};
    if (traceRunId !== null && traceRunId !== undefined) {
      trace.meta.trace_run_id = traceRunId;
    } else if (trace.meta.trace_run_id === undefined || trace.meta.trace_run_id === null) {
      const derivedRunId = deriveTraceRunIdFromPath(jsonPath);
      if (derivedRunId !== null) trace.meta.trace_run_id = derivedRunId;
    }
    ensureTraceDisasmPath(trace, jsonPath);
    const effectiveSourcePath = String(
      sourcePath || trace.meta.source || trace.meta.source_enrichment?.sourcePath || ''
    ).trim();
    if (effectiveSourcePath) {
      const sourceEnrichment = buildSourceEnrichmentMeta({
        sourcePath: effectiveSourcePath,
        trace,
        archBits: Number(trace?.meta?.arch_bits || archBits)
      });
      if (sourceEnrichment) {
        trace.meta.source_enrichment = sourceEnrichment;
        trace.meta.source = sourceEnrichment?.sourcePath || effectiveSourcePath;
      }
    }
    attachTraceAddressEnrichment(trace, { symbols });
    setViewMode(trace, trace.meta.view_mode || viewMode);
    return trace;
  };

  const buildDynamicTraceHistoryItems = () => {
    const tempDir = storageDir;
    if (!tempDir || !fs.existsSync(tempDir)) return [];
    const activePath = normalizeHistoryPath(_activeDynamicTracePath);
    const candidates = fs.readdirSync(tempDir)
      .filter((name) => /^output\.run-\d+-.*\.json$/.test(name));

    return candidates.map((name) => {
      const absolutePath = path.join(tempDir, name);
      let stat = null;
      let trace = null;
      try {
        stat = fs.statSync(absolutePath);
        trace = readTraceJson(absolutePath);
      } catch (_) {
        return null;
      }
      const snapshots = Array.isArray(trace?.snapshots) ? trace.snapshots : [];
      const meta = trace?.meta && typeof trace.meta === 'object' ? trace.meta : {};
      const payloadText = String(meta.payload_text || meta.argv1 || '');
      const payloadLabel = String(meta.payload_label || payloadTargetLabel(meta.payload_target || 'argv1'));
      const runId = Number(meta.trace_run_id || deriveTraceRunIdFromPath(name) || 0);
      const updatedAtMs = Number(stat?.mtimeMs || 0);
      const binaryPath = String(meta.binary || '').trim();
      const sourcePath = String(meta.source || meta.source_enrichment?.sourcePath || '').trim();
      const previewLimit = 22;
      return {
        path: absolutePath,
        fileName: name,
        runId,
        steps: snapshots.length,
        argvBytes: payloadText.length,
        argvPreview: payloadText.length > previewLimit ? `${payloadText.slice(0, previewLimit)}...` : payloadText,
        payloadLabel,
        binaryName: binaryPath ? path.basename(binaryPath) : '',
        sourceName: sourcePath ? path.basename(sourcePath) : '',
        startSymbol: String(meta.start_symbol || '').trim(),
        updatedAtMs,
        updatedAtLabel: updatedAtMs
          ? new Date(updatedAtMs).toLocaleString('fr-FR', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            day: '2-digit',
            month: '2-digit'
          })
          : '',
        active: normalizeHistoryPath(absolutePath) === activePath
      };
    })
      .filter(Boolean)
      .sort((left, right) => {
        const runDiff = Number(right.runId || 0) - Number(left.runId || 0);
        if (runDiff !== 0) return runDiff;
        return Number(right.updatedAtMs || 0) - Number(left.updatedAtMs || 0);
      });
  };

  const postDynamicTraceHistory = () => {
    panel.webview.postMessage({
      type: 'dynamicTraceHistory',
      activeTracePath: _activeDynamicTracePath || '',
      items: buildDynamicTraceHistoryItems()
    });
  };

  const notifyDynamicTraceCleared = (tracePath = '', reason = 'cleared') => {
    panel.webview.postMessage({
      type: 'dynamicTraceCleared',
      tracePath: String(tracePath || ''),
      reason
    });
    if (openVisualizerWebview && typeof openVisualizerWebview.clearCurrentTrace === 'function') {
      openVisualizerWebview.clearCurrentTrace({
        tracePath: String(tracePath || ''),
        reason
      });
    }
  };

  const isManagedDynamicTracePath = (targetPath) => {
    const normalized = normalizeHistoryPath(targetPath);
    const tempDir = normalizeHistoryPath(storageDir || (ensureTempDir ? ensureTempDir(root) : ''));
    const fileName = path.basename(normalized);
    return Boolean(
      normalized &&
      normalized.startsWith(tempDir + path.sep) &&
      /^output\.run-\d+-.*\.json$/.test(fileName)
    );
  };

  const deleteDynamicTraceArtifacts = (tracePath) => {
    if (!isManagedDynamicTracePath(tracePath)) return false;
    const jsonPath = normalizeHistoryPath(tracePath);
    const disasmPath = jsonPath.endsWith('.json') ? `${jsonPath.slice(0, -5)}.disasm.asm` : '';
    let removed = false;
    [jsonPath, disasmPath].filter(Boolean).forEach((candidate) => {
      if (fs.existsSync(candidate)) {
        fs.unlinkSync(candidate);
        removed = true;
      }
    });
    if (normalizeHistoryPath(_activeDynamicTracePath) === jsonPath) {
      _activeDynamicTracePath = '';
      notifyDynamicTraceCleared(jsonPath, 'deleted');
    }
    return removed;
  };

  return {
    // State accessors
    getActiveDynamicTracePath,
    setActiveDynamicTracePath,
    // Utility functions (needed externally e.g. by runTrace handler in hub.ts)
    enrichTraceForVisualizer,
    buildTraceRunArtifacts,
    buildDynamicTraceHistoryItems,
    postDynamicTraceHistory,
    deleteDynamicTraceArtifacts,
    // Message handlers (for dispatcher map)
    requestDynamicTraceHistory: async (_msg) => {
      postDynamicTraceHistory();
    },
    openDynamicTraceHistory: async (message) => {
      const requestedTracePath = String(message.tracePath || '').trim();
      if (!isManagedDynamicTracePath(requestedTracePath) || !fs.existsSync(requestedTracePath)) {
        vscode.window.showErrorMessage('Trace historique introuvable.');
        postDynamicTraceHistory();
        return;
      }
      if (normalizeHistoryPath(requestedTracePath) === normalizeHistoryPath(_activeDynamicTracePath)) {
        const revealed = typeof openVisualizerWebview?.revealCurrentTrace === 'function'
          ? openVisualizerWebview.revealCurrentTrace()
          : false;
        if (revealed) {
          return;
        }
      }
      const trace = readTraceJson(requestedTracePath);
      enrichTraceForVisualizer(trace, {
        jsonPath: requestedTracePath,
        viewMode: trace?.meta?.view_mode || 'dynamic'
      });
      _activeDynamicTracePath = requestedTracePath;
      writeTraceJson(requestedTracePath, trace);
      openVisualizerWebview(trace);
      postDynamicTraceHistory();
    },
    deleteDynamicTraceHistory: async (message) => {
      const requestedTracePath = String(message.tracePath || '').trim();
      deleteDynamicTraceArtifacts(requestedTracePath);
      postDynamicTraceHistory();
    },
    clearDynamicTraceHistory: async (_msg) => {
      const items = buildDynamicTraceHistoryItems();
      items.forEach((item) => {
        deleteDynamicTraceArtifacts(item.path);
      });
      postDynamicTraceHistory();
    },
  };
}

module.exports = { createTraceHistory };
