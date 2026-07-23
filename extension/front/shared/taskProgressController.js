/**
 * Global task progress controller for the hub webview.
 * Tracks long-running requests sent to the extension and keeps users oriented.
 */
(function initTaskProgressController(global) {
  const TASK_TIMEOUT_MS = 120000;
  const HIDE_DELAY_MS = 700;
  const PROGRESS_MESSAGES = new Set(['hubDecompilerPullProgress', 'hubPluginProgress', 'hubAutoTriageEvent']);
  const FINISH_MESSAGES = new Set([
    'accountState',
    'compileResult',
    'compilerListResult',
    'hubAiProvidersResult',
    'hubAttck',
    'hubAutoFromCmpResult',
    'hubAutoTriageDone',
    'hubCallGraph',
    'hubCfg',
    'hubCommandResult',
    'hubDecompilerImageUpdates',
    'hubDecompilerList',
    'hubDecompilerPullDone',
    'hubDecompile',
    'hubDisasmReady',
    'hubDiscoveredFunctions',
    'hubError',
    'hubExceptionHandlersDone',
    'hubExportsDone',
    'hubFunctionsDone',
    'hubHexView',
    'hubImportXrefsDone',
    'hubImportsDone',
    'hubOllamaModels',
    'hubOllamaResult',
    'hubPatchResult',
    'hubPatchesDone',
    'hubPeResourcesDone',
    'hubPluginState',
    'hubPluginResult',
    'hubRecherche',
    'hubRedoPatchDone',
    'hubRevertPatchDone',
    'hubRuleContent',
    'hubRulesPath',
    'hubScriptLoaded',
    'hubScriptResult',
    'hubScriptSaved',
    'hubSearchBinaryResult',
    'hubSections',
    'hubStaticCompileDone',
    'hubStrings',
    'hubStructsDone',
    'hubStructsSaved',
    'hubSymbols',
    'hubTypedDataDone',
    'hubTypedStructPreviewDone',
    'hubXrefs',
    'pluginStatusRefresh',
    'runTraceDone',
    'symbols',
  ]);

  const TASK_DEFINITIONS = {
    hubAiProviderDefaultSet: task('Mise a jour IA', ['hubAiProvidersResult', 'hubError']),
    hubAiProviderSet: task('Configuration IA', ['hubAiProvidersResult', 'hubError']),
    hubAiProvidersGet: task('Chargement fournisseurs IA', ['hubAiProvidersResult']),
    hubAutoFromCmp: task('Recherche payload CMP', ['hubAutoFromCmpResult', 'hubError']),
    hubExecuteCommand: task('Execution commande', ['hubCommandResult', 'hubDecompilerList', 'hubError']),
    hubInstallDecompiler: task('Installation decompilateur', ['hubDecompilerList', 'hubError']),
    hubListDecompilers: task('Etat des decompilateurs', ['hubDecompilerList', 'hubError']),
    hubLoadCallGraph: task('Construction call graph', ['hubCallGraph', 'hubError']),
    hubLoadCfg: task('Construction CFG', ['hubCfg', 'hubError']),
    hubLoadDecompile: task('Decompilation', ['hubDecompile', 'hubError']),
    hubLoadDiscoveredFunctions: task('Decouverte fonctions', ['hubDiscoveredFunctions', 'hubError']),
    hubLoadExceptionHandlers: task('Chargement exceptions', ['hubExceptionHandlersDone', 'hubError']),
    hubLoadExports: task('Chargement exports', ['hubExportsDone', 'hubError']),
    hubLoadFunctions: task('Analyse fonctions', ['hubFunctionsDone', 'hubError']),
    hubLoadHexView: task('Chargement hex view', ['hubHexView', 'hubError']),
    hubLoadImportXrefs: task('References imports', ['hubImportXrefsDone', 'hubError']),
    hubLoadImports: task('Analyse imports', ['hubImportsDone', 'hubError']),
    hubLoadPatches: task('Chargement patches', ['hubPatchesDone', 'hubError']),
    hubLoadPeResources: task('Extraction ressources PE', ['hubPeResourcesDone', 'hubError']),
    hubLoadPluginState: task('Actualisation plugins', ['hubPluginState', 'pluginStatusRefresh', 'hubError']),
    hubLoadScript: task('Chargement script', ['hubScriptLoaded', 'hubError']),
    hubLoadSections: task('Chargement sections', ['hubSections', 'hubError']),
    hubLoadStackFrame: task('Analyse stack frame', ['hubStackFrame', 'hubError']),
    hubLoadStrings: task('Chargement strings', ['hubStrings', 'hubError']),
    hubLoadStructs: task('Chargement structs', ['hubStructsDone', 'hubError']),
    hubLoadSymbols: task('Chargement symboles', ['hubSymbols', 'symbols', 'hubError']),
    hubLoadTypedData: task('Analyse donnees typees', ['hubTypedDataDone', 'hubError']),
    hubLoadXrefs: task('References croisees', ['hubXrefs', 'hubError']),
    hubOllamaListModels: task('Recherche modeles IA', ['hubOllamaModels', 'hubOllamaResult', 'hubError']),
    hubOllamaPrompt: task('Generation IA', ['hubOllamaResult', 'hubError'], { timeoutMs: 240000 }),
    hubOpenDisasm: task('Desassemblage', ['hubDisasmReady', 'hubError']),
    hubPatchBytes: task('Application patch', ['hubPatchResult', 'hubError']),
    hubPullDecompilerImage: task('Image decompilateur', ['hubDecompilerPullDone', 'hubError'], { timeoutMs: 600000 }),
    hubPluginInvoke: task('Execution plugin', ['hubPluginResult', 'hubError'], { timeoutMs: 240000 }),
    hubRedoPatch: task('Reapplication patch', ['hubRedoPatchDone', 'hubError']),
    hubRunScript: task('Execution script', ['hubScriptResult', 'hubError']),
    hubSaveScript: task('Sauvegarde script', ['hubScriptSaved', 'hubError']),
    hubSaveStructs: task('Sauvegarde structs', ['hubStructsSaved', 'hubError']),
    hubSearchBinary: task('Recherche binaire', ['hubSearchBinaryResult', 'hubRecherche', 'hubError']),
    hubStaticCompile: task('Compilation', ['compileResult', 'hubStaticCompileDone', 'hubError']),
    hubUseBinaryPath: task('Chargement binaire', ['hubSetBinaryPath', 'accountState', 'hubError']),
    runTrace: task('Trace dynamique', ['runTraceDone', 'hubError'], { timeoutMs: 240000 }),
  };

  function task(label, doneTypes, options) {
    return {
      label,
      doneTypes: new Set(doneTypes || []),
      timeoutMs: Number(options?.timeoutMs || TASK_TIMEOUT_MS),
    };
  }

  const state = {
    tasks: new Map(),
    sequence: 0,
    hideTimer: 0,
    els: null,
    originalPostMessage: null,
  };

  function ensureUi() {
    if (state.els) return state.els;
    const root = global.document?.createElement('div');
    if (!root) return null;
    root.id = 'pof-task-progress';
    root.className = 'task-progress-shell';
    root.hidden = true;
    root.setAttribute('role', 'status');
    root.setAttribute('aria-live', 'polite');
    root.innerHTML = [
      '<div class="task-progress-card">',
      '  <div class="task-progress-spinner" aria-hidden="true"></div>',
      '  <div class="task-progress-copy">',
      '    <div class="task-progress-title">Traitement en cours</div>',
      '    <div class="task-progress-detail">Preparation...</div>',
      '    <div class="task-progress-track" aria-hidden="true"><div class="task-progress-bar"></div></div>',
      '    <details class="task-progress-details">',
      '      <summary>Details des taches</summary>',
      '      <div class="task-progress-list"></div>',
      '    </details>',
      '  </div>',
      '  <div class="task-progress-count" aria-hidden="true"></div>',
      '</div>',
    ].join('');
    global.document.body.appendChild(root);
    state.els = {
      root,
      title: root.querySelector('.task-progress-title'),
      detail: root.querySelector('.task-progress-detail'),
      bar: root.querySelector('.task-progress-bar'),
      count: root.querySelector('.task-progress-count'),
      details: root.querySelector('.task-progress-details'),
      list: root.querySelector('.task-progress-list'),
    };
    return state.els;
  }

  function normalizeMessageType(message) {
    return String(message?.type || '').trim();
  }

  function startTask(message) {
    const messageType = normalizeMessageType(message);
    const definition = TASK_DEFINITIONS[messageType];
    if (!definition) return '';
    ensureRequestId(message, messageType);
    const id = `${messageType}:${message?.requestId || message?.decompiler || message?.addr || ++state.sequence}`;
    const existing = state.tasks.get(id);
    if (existing?.timeoutId) global.clearTimeout(existing.timeoutId);
    const timeoutId = global.setTimeout(() => finishTask(id), definition.timeoutMs);
    state.tasks.set(id, {
      id,
      requestId: String(message?.requestId || ''),
      messageType,
      label: getTaskLabel(message, definition.label),
      detail: getInitialDetail(message, definition.label),
      doneTypes: definition.doneTypes,
      percent: null,
      timeoutId,
      startedAt: Date.now(),
    });
    render();
    return id;
  }

  function ensureRequestId(message, messageType) {
    if (!message || typeof message !== 'object' || message.requestId) return;
    if (messageType !== 'hubPluginInvoke') return;
    message.requestId = `plugin-${Date.now()}-${++state.sequence}`;
  }

  function humanizeFeature(feature) {
    const raw = String(feature || '').trim();
    const labels = {
      anti_analysis: 'Anti-analyse',
      attck: 'ATT&CK',
      behavior: 'Comportement',
      bindiff: 'BinDiff',
      capa_scan: 'CAPA',
      cross_analysis: 'Cross-analysis',
      deobfuscate: 'Deobfuscation',
      flirt: 'FLIRT',
      func_similarity: 'Similarite',
      packer: 'Packer',
      rop: 'ROP',
      rop_build: 'ROP chain',
      taint: 'Taint',
      vulns: 'Vulnerabilites',
      yara_scan: 'YARA',
    };
    return labels[raw] || raw.replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  }

  function getTaskLabel(message, fallback) {
    if (normalizeMessageType(message) === 'hubPluginInvoke') {
      const feature = String(message?.feature || message?.featureId || '').trim();
      return feature ? `Plugin: ${humanizeFeature(feature)}` : 'Plugin';
    }
    return fallback;
  }

  function getInitialDetail(message, fallback) {
    const parts = [];
    if (normalizeMessageType(message) === 'hubPluginInvoke') {
      const payload = message?.payload && typeof message.payload === 'object' ? message.payload : {};
      const binaryPath = String(message?.binaryPath || payload.binaryPath || payload.binary_path || '').trim();
      const action = String(payload.action || '').trim();
      if (action) parts.push(action);
      if (binaryPath) parts.push(binaryPath.split(/[\\/]/).pop());
      return parts.length ? parts.join(' - ') : 'Execution en arriere-plan';
    }
    if (message?.decompiler) parts.push(String(message.decompiler));
    if (message?.command) parts.push(String(message.command).replace(/^pileOuFace\./, ''));
    if (message?.symbol) parts.push(String(message.symbol));
    if (message?.addr) parts.push(String(message.addr));
    if (message?.section) parts.push(String(message.section));
    return parts.length ? parts.join(' - ') : fallback;
  }

  function finishTask(id) {
    const active = state.tasks.get(id);
    if (active?.timeoutId) global.clearTimeout(active.timeoutId);
    state.tasks.delete(id);
    render();
  }

  function finishMatching(message) {
    const messageType = normalizeMessageType(message);
    if (!FINISH_MESSAGES.has(messageType)) return;
    const matching = [];
    const requestId = String(message?.requestId || '');
    state.tasks.forEach((entry, id) => {
      if (requestId && entry.requestId && entry.requestId !== requestId) return;
      if (messageType === 'hubPluginResult' && entry.messageType !== 'hubPluginInvoke') return;
      if (entry.doneTypes.has(messageType) || messageType === 'hubError') matching.push(id);
    });
    matching.forEach(finishTask);
  }

  function updateProgress(message) {
    const messageType = normalizeMessageType(message);
    if (!PROGRESS_MESSAGES.has(messageType)) return false;
    let updated = false;
    state.tasks.forEach((entry) => {
      if (messageType === 'hubPluginProgress') {
        if (entry.messageType !== 'hubPluginInvoke') return;
        const requestId = String(message?.requestId || '');
        if (requestId && entry.requestId && entry.requestId !== requestId) return;
        const percent = Number(message.percent);
        entry.percent = Number.isFinite(percent) ? Math.max(0, Math.min(100, percent)) : null;
        entry.detail = String(message.message || entry.detail || entry.label);
        updated = true;
        return;
      }
      if (!entry.doneTypes.has('hubDecompilerPullDone')) return;
      if (message.decompiler && entry.id.indexOf(`:${message.decompiler}`) === -1) return;
      const percent = Number(message.percent);
      entry.percent = Number.isFinite(percent) ? Math.max(0, Math.min(100, percent)) : null;
      entry.detail = String(message.line || entry.detail || entry.label);
      updated = true;
    });
    if (updated) render();
    return updated;
  }

  function getCurrentTask() {
    let selected = null;
    state.tasks.forEach((entry) => {
      if (!selected || entry.startedAt > selected.startedAt) selected = entry;
    });
    return selected;
  }

  function render() {
    const els = ensureUi();
    if (!els) return;
    const active = getCurrentTask();
    if (!active) {
      if (state.hideTimer) global.clearTimeout(state.hideTimer);
      state.hideTimer = global.setTimeout(() => {
        els.root.hidden = true;
        els.root.classList.remove('is-active', 'has-percent');
        els.root.removeAttribute('aria-busy');
      }, HIDE_DELAY_MS);
      return;
    }
    if (state.hideTimer) {
      global.clearTimeout(state.hideTimer);
      state.hideTimer = 0;
    }
    const count = state.tasks.size;
    els.root.hidden = false;
    els.root.classList.add('is-active');
    els.root.setAttribute('aria-busy', 'true');
    els.title.textContent = active.label || 'Traitement en cours';
    els.detail.textContent = active.detail || active.label || '';
    els.count.textContent = count > 1 ? `${count} taches` : '';
    renderTaskList(els);
    if (Number.isFinite(active.percent)) {
      els.root.classList.add('has-percent');
      els.bar.style.width = `${active.percent}%`;
    } else {
      els.root.classList.remove('has-percent');
      els.bar.style.width = '';
    }
  }

  function renderTaskList(els) {
    if (!els.list || !els.details) return;
    const entries = Array.from(state.tasks.values()).sort((a, b) => a.startedAt - b.startedAt);
    els.details.hidden = entries.length <= 1;
    els.list.replaceChildren(...entries.map((entry) => {
      const row = global.document.createElement('div');
      row.className = 'task-progress-row';
      const title = global.document.createElement('span');
      title.className = 'task-progress-row-title';
      title.textContent = entry.label || 'Tache';
      const detail = global.document.createElement('span');
      detail.className = 'task-progress-row-detail';
      detail.textContent = entry.detail || '';
      row.append(title, detail);
      return row;
    }));
  }

  function wrapPostMessage() {
    const bus = global.POFHubMessageBus;
    const vscode = bus?.vscode;
    if (!vscode || typeof vscode.postMessage !== 'function' || bus.__pofTaskProgressWrapped) return;
    state.originalPostMessage = vscode.postMessage.bind(vscode);
    const trackedPostMessage = function trackedPostMessage(message) {
      try { startTask(message); } catch(e) { console.error('[POFTaskProgress] startTask error', e); }
      return state.originalPostMessage(message);
    };
    // Mutate the existing object so already-captured references (e.g. state.js) see the patch.
    vscode.postMessage = trackedPostMessage;
    bus.postMessage = trackedPostMessage;
    bus.__pofTaskProgressWrapped = true;
  }

  function onMessage(event) {
    const message = event?.data || {};
    if (updateProgress(message)) return;
    finishMatching(message);
  }

  function init() {
    ensureUi();
    wrapPostMessage();
    global.addEventListener('message', onMessage);
  }

  const api = {
    finishTask,
    startTask,
    updateProgress,
  };

  init();
  global.POFHubTaskProgressController = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.taskProgressController = api;
  }
})(globalThis);
