// Messages from extension
function initMessageHandler() {
function reportStaticWebviewPerf(event, startedAt, details = {}) {
  window.reportPofWebviewPerf?.(event, {
    elapsedMs: Math.round((performance.now() - startedAt) * 10) / 10,
    ...details,
  }, { afterPaint: true });
}

function isStaleStaticBinaryResponse(msg, scope) {
  const normalize = (value) => String(value || '').trim().replace(/\\/g, '/');
  const currentBinaryPath = typeof getStaticBinaryPath === 'function' ? getStaticBinaryPath() : '';
  const responseBinaryPath = String(msg?.binaryPath || '').trim();
  if (!responseBinaryPath || !currentBinaryPath || normalize(responseBinaryPath) === normalize(currentBinaryPath)) {
    return false;
  }
  vscode.postMessage({
    type: 'hubDebugLog',
    scope,
    event: 'ignored-stale-response',
    details: { currentBinaryPath, responseBinaryPath },
  });
  return true;
}

function refreshDisasmForAnnotations(binaryPath, annotations) {
  const bp = String(binaryPath || (typeof getStaticBinaryPath === 'function' ? getStaticBinaryPath() : '') || '').trim();
  if (!bp || !annotations || typeof annotations !== 'object') return false;
  const relevantEntries = Object.entries(annotations)
    .filter(([, entry]) => entry && (entry.name || entry.comment));
  const signature = `${bp}\n${JSON.stringify(relevantEntries)}`;
  const previous = window._lastAnnotationDisasmRefreshSignature;
  if (window._adoptAnnotationDisasmSignatureFor === bp) {
    // Le .asm vient d'être régénéré : disasm.py a déjà baké l'état courant
    // des annotations (SQLite), adopter la signature sans relancer de build.
    window._adoptAnnotationDisasmSignatureFor = null;
    window._lastAnnotationDisasmRefreshSignature = signature;
    return false;
  }
  if (previous === signature) return false;
  window._lastAnnotationDisasmRefreshSignature = signature;
  // Ne rebuild sur liste vide que si ce binaire avait un overlay baké
  // (suppression de la dernière annotation) — pas au premier chargement.
  const previousSameBinary = typeof previous === 'string' && previous.startsWith(`${bp}\n`);
  if (!relevantEntries.length && !previousSameBinary) return false;
  vscode.postMessage({
    type: 'hubOpenDisasm',
    binaryPath: bp,
    useCache: false,
    openInEditor: false,
    refreshReason: 'annotation-overlay',
  });
  return true;
}

function isAnnotatedFunctionAddress(addr) {
  const normalized = typeof normalizeHexAddress === 'function' ? normalizeHexAddress(addr) : String(addr || '').trim();
  if (!normalized) return false;
  if (window.annotationFunctionAddrs instanceof Set && window.annotationFunctionAddrs.has(normalized)) return true;
  const decompileSelect = document.getElementById('decompileAddrSelect');
  if (decompileSelect && Array.from(decompileSelect.options).some((opt) => opt.value === normalized)) return true;
  if (typeof getFunctionRowByAddr === 'function' && getFunctionRowByAddr(normalized)) return true;
  const knownFunctionSources = [
    window.functionListCache || [],
    window.discoveredFunctionsCache || [],
    window.symbolsCache || [],
  ];
  return knownFunctionSources.some((source) => (Array.isArray(source) ? source : []).some((entry) => {
    const entryAddr = typeof normalizeHexAddress === 'function' ? normalizeHexAddress(entry?.addr || '') : String(entry?.addr || '').trim();
    return entryAddr === normalized;
  }));
}

function focusAnnotationEditor(addr, annotation = null, options = {}) {
  const normalized = typeof normalizeHexAddress === 'function' ? normalizeHexAddress(addr) : String(addr || '').trim();
  if (!normalized) return;
  const entry = annotation || window._annotations?.[normalized] || {};
  const goInput = document.getElementById('goToAddrInput');
  if (goInput) goInput.value = normalized;
  const badge = document.getElementById('annotationAddrBadge');
  if (badge) { badge.textContent = normalized; badge.dataset.addr = normalized; badge.classList.add('has-addr'); }
  const btn = document.getElementById('btnAddAnnotation');
  if (btn) {
    btn.disabled = false;
    btn.textContent = entry?.name || entry?.comment ? 'Modifier' : 'Annoter';
    btn.title = entry?.name || entry?.comment ? 'Modifier cette annotation' : 'Annoter cette adresse';
  }
  const commentEl = document.getElementById('annotationComment');
  if (commentEl) {
    commentEl.value = entry?.comment || '';
    if (options.focus !== false) {
      commentEl.focus();
      commentEl.select?.();
    }
  }
  const nameEl = document.getElementById('annotationName');
  if (nameEl) nameEl.value = entry?.name || '';
}

function renderAnnotationsList(annotations = window._annotations || {}) {
  const listEl = document.getElementById('annotationsList');
  if (!listEl) return false;
  const entries = Object.entries(annotations).filter(([, v]) => v && (v.comment || v.name));
  if (entries.length === 0) {
    listEl.replaceChildren();
    const p = document.createElement('p');
    p.className = 'hint annotations-empty';
    p.textContent = 'Aucune annotation.';
    listEl.appendChild(p);
    return true;
  }
  listEl.replaceChildren();
  entries.forEach(([addr, v]) => {
    const item = document.createElement('div');
    const isFunctionAnnotation = isAnnotatedFunctionAddress(addr);
    item.className = `annotation-item ${isFunctionAnnotation ? 'annotation-item-function' : 'annotation-item-note'}`;

    const addrCode = document.createElement('code');
    addrCode.className = 'addr-link';
    addrCode.dataset.addr = addr;
    addrCode.textContent = addr;
    item.appendChild(addrCode);

    const kindBadge = document.createElement('span');
    kindBadge.className = `ann-kind ${isFunctionAnnotation ? 'ann-kind-function' : 'ann-kind-note'}`;
    kindBadge.textContent = isFunctionAnnotation ? 'Fonction' : 'Annotation';
    kindBadge.title = isFunctionAnnotation
      ? 'Rename/commentaire posé sur une adresse de fonction'
      : 'Annotation posée sur une instruction ou adresse interne';
    item.appendChild(kindBadge);

    const meta = document.createElement('div');
    meta.className = 'ann-meta';
    if (v.name) {
      const nameSpan = document.createElement('span');
      nameSpan.className = 'ann-name';
      nameSpan.textContent = '→ ' + v.name;
      meta.appendChild(nameSpan);
    }
    if (v.comment) {
      const cmtSpan = document.createElement('span');
      cmtSpan.className = 'ann-comment';
      cmtSpan.textContent = v.comment.length > 80 ? v.comment.substring(0, 80) + '…' : v.comment;
      cmtSpan.title = v.comment;
      meta.appendChild(cmtSpan);
    }
    item.appendChild(meta);

    const editBtn = document.createElement('button');
    editBtn.className = 'btn btn-sm ann-edit';
    editBtn.textContent = 'Modifier';
    editBtn.title = 'Modifier cette annotation';
    editBtn.dataset.addr = addr;
    item.appendChild(editBtn);

    const delBtn = document.createElement('button');
    delBtn.className = 'btn btn-sm ann-delete';
    delBtn.textContent = '×';
    delBtn.title = 'Supprimer cette annotation';
    delBtn.dataset.addr = addr;
    item.appendChild(delBtn);

    listEl.appendChild(item);
  });

  listEl.querySelectorAll('.addr-link').forEach((link) => {
    link.style.cursor = 'pointer';
    link.addEventListener('click', () => {
      const a = link.dataset.addr;
      const ann = annotations[a];
      focusAnnotationEditor(a, ann, { focus: false });
      vscode.postMessage({ type: 'hubGoToAddress', addr: a, binaryPath: getStaticBinaryPath() });
    });
  });

  listEl.querySelectorAll('.ann-edit').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const a = btn.dataset.addr;
      focusAnnotationEditor(a, annotations[a]);
    });
  });

  listEl.querySelectorAll('.ann-delete').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      vscode.postMessage({ type: 'hubDeleteAnnotation', binaryPath: getStaticBinaryPath(), addr: btn.dataset.addr });
    });
  });

  return true;
}

function mergeAnnotationFunctionAddrs(addrs) {
  const target = window.annotationFunctionAddrs instanceof Set ? window.annotationFunctionAddrs : new Set();
  (Array.isArray(addrs) ? addrs : []).forEach((addr) => {
    const normalized = typeof normalizeHexAddress === 'function' ? normalizeHexAddress(addr) : String(addr || '').trim();
    if (normalized) target.add(normalized);
  });
  window.annotationFunctionAddrs = target;
  return target;
}

window.addEventListener('message', (event) => {
  const msg = event.data;
  if (!msg?.type) return;
  // Forward plugin results to the plugin's iframe (no return — other handlers also need this)
  if (msg.type === 'hubPluginResult' && window.PluginIframeRouter) {
    window.PluginIframeRouter.dispatch(msg.plugin_id, msg);
  }
  if (msg.type === 'hubPluginProgress' && window.PluginIframeRouter) {
    window.PluginIframeRouter.broadcast(msg);
  }
  // Generic host replies (e.g. file picker, rules manager) that plugin iframes may also be waiting on
  const BROADCAST_TO_PLUGINS = new Set([
    'hubPickedFile', 'hubRulesList', 'hubRulesPath', 'hubRuleContent',
    'hubRuleToggled', 'hubRuleAdded', 'hubRuleUpdated', 'hubRuleDeleted',
    'hubPluginState',
  ]);
  if (BROADCAST_TO_PLUGINS.has(msg.type) && window.PluginIframeRouter) {
    window.PluginIframeRouter.broadcast(msg);
  }
  if (msg.type === 'hubPrefillAiPrompt') {
    prefillOllamaPrompt(String(msg.prompt || ''));
    return;
  }
  if (msg.type === 'showPanel' && msg.panel) {
    showPanel(msg.panel);
    if (msg.focusGoToAddr) {
      setTimeout(() => {
        const input = document.getElementById('goToAddrInput');
        if (input) { input.focus(); input.select(); }
      }, 300);
    }
    return;
  }
  if (msg.type === 'platformInfo') {
    currentPlatform = msg.platform || currentPlatform;
    setOption32Availability(document.getElementById('archBits'), msg.platform);
    setOption32Availability(document.getElementById('gccArch'), msg.platform);
    return;
  }
  if (msg.type === 'hubPerfDiagnosticsConfig') {
    window.POF_PERF_DIAGNOSTICS_ENABLED = Boolean(msg.enabled);
    return;
  }
  if (msg.type === 'hubPerfSnapshotRequest') {
    if (!window.POF_PERF_DIAGNOSTICS_ENABLED) return;
    window.capturePofWebviewPerfSnapshot?.('manual.snapshot', {
      source: String(msg.source || 'host'),
    });
    return;
  }
  if (msg.type === 'hubPluginState') {
    clearPluginTabs();
    const incomingState = msg.state && typeof msg.state === 'object' ? msg.state : {};
    registerPluginTabs(incomingState.tabRegistrations || []);
    pluginUiState = { ...pluginUiState, ...incomingState };
    renderPluginManager(pluginUiState);
    refreshStaticNavigationForSettings();
    renderStaticFeatureSettings();
    return;
  }
  if (msg.type === 'pluginStatusRefresh') {
    const prevPlugins = Array.isArray(pluginUiState.plugins) ? pluginUiState.plugins : [];
    const prevStatusById = {};
    prevPlugins.forEach((p) => { if (p?.id) prevStatusById[p.id] = p.licenseStatus; });
    const newPayload = Array.isArray(msg.payload) ? msg.payload : [];
    pluginUiState = {
      ...pluginUiState,
      plugins: newPayload,
    };
    renderPluginManager(pluginUiState);
    refreshStaticNavigationForSettings();
    renderStaticFeatureSettings();
    const activeStatuses = new Set(['unlocked', 'grace']);
    const lockedStatuses = new Set(['expired', 'clock_tampered']);
    newPayload.forEach((p) => {
      if (!p?.id) return;
      const prev = prevStatusById[p.id];
      const next = p.licenseStatus;
      if (activeStatuses.has(prev) && lockedStatuses.has(next)) {
        _showToast({
          title: 'Licence expirée',
          sub: `${p.id} : ${next}`,
          icon: '🔒',
          variant: 'error',
          duration: 6000,
        });
      }
    });
    return;
  }
  if (msg.type === 'hubPluginFolderOpened') {
    if (msg.ok) {
      _showToast({
        title: 'Dossier plugins ouvert',
        sub: String(msg.path || ''),
        icon: '📦',
        variant: 'ready',
        duration: 3500,
      });
      vscode.postMessage({ type: 'hubLoadPluginState' });
    } else {
      _showToast({
        title: 'Ouverture du dossier plugins impossible',
        sub: String(msg.error || msg.path || ''),
        icon: '⚠️',
        variant: 'error',
        duration: 4500,
      });
    }
    return;
  }
  if (msg.type === 'hubLicenseFolderOpened') {
    if (msg.ok) {
      _showToast({
        title: 'Dossier licences ouvert',
        sub: String(msg.path || ''),
        icon: '🔑',
        variant: 'ready',
        duration: 3500,
      });
      vscode.postMessage({ type: 'hubLoadPluginState' });
    } else {
      _showToast({
        title: 'Ouverture du dossier licences impossible',
        sub: String(msg.error || msg.path || ''),
        icon: '⚠️',
        variant: 'error',
        duration: 4500,
      });
    }
    return;
  }
  if (msg.type === 'hubPluginInstalled') {
    if (msg.cancelled) return;
    if (msg.ok) {
      _showToast({
        title: 'Plugin installé',
        sub: String(msg.plugin_id || msg.installed_to || msg.source || ''),
        icon: '📦',
        variant: 'ready',
        duration: 4200,
      });
      vscode.postMessage({ type: 'hubLoadPluginState' });
    } else {
      _showToast({
        title: 'Installation du plugin impossible',
        sub: String(msg.error || msg.source || ''),
        icon: '⚠️',
        variant: 'error',
        duration: 5200,
      });
    }
    return;
  }
  if (msg.type === 'hubPluginLicenseInstalled') {
    if (msg.cancelled) return;
    if (msg.ok) {
      _showToast({
        title: 'Licence importée',
        sub: String(msg.plugin_id || msg.installed_to || msg.source || ''),
        icon: '🔑',
        variant: 'ready',
        duration: 4200,
      });
      vscode.postMessage({ type: 'hubLoadPluginState' });
    } else {
      _showToast({
        title: 'Import de licence impossible',
        sub: String(msg.error || msg.source || ''),
        icon: '⚠️',
        variant: 'error',
        duration: 5200,
      });
    }
    return;
  }
  if (msg.type === 'hubRuleImported') {
    const results = Array.isArray(msg.results) ? msg.results : [];
    const failed = results.filter(function(r) { return !r.ok; });
    if (failed.length) {
      _showToast({
        title: failed.length + ' fichier(s) non importé(s)',
        sub: failed.map(function(r) { return r.name; }).join(', '),
        icon: '⚠️',
        variant: 'error',
        duration: 5000,
      });
    } else if (results.length) {
      _showToast({
        title: results.length + ' fichier(s) importé(s)',
        sub: results.map(function(r) { return r.name; }).join(', '),
        icon: '✓',
        variant: 'success',
        duration: 3000,
      });
    }
    return;
  }
  if (msg.type === 'hubOllamaModels') {
    setOllamaBusy(false);
    if (msg.error) {
      setOllamaStatus(msg.error, true);
      if (!ollamaUiState.models.length) renderOllamaModels([], '');
      return;
    }
    const models = Array.isArray(msg.models) ? msg.models : [];
    const preferredModel = String(msg.preferredModel || ollamaUiState.lastModel || '').trim();
    if (preferredModel) rememberOllamaModel(preferredModel);
    ollamaUiState.models = models;
    renderOllamaModels(models, preferredModel);
    if (!models.length) {
      setOllamaStatus('Aucun modèle trouvé. Vérifie Ollama et le pull du modèle.', true);
      return;
    }
    const selected = getCurrentOllamaModel() || models[0];
    setOllamaStatus(`${models.length} modèle(s) détecté(s). Sélection active: ${selected}`);
    return;
  }
  if (msg.type === 'hubOllamaStream') {
    if (msg.requestId && msg.requestId !== activeAiRequestId) return;
    const evt = msg.event || {};
    if (evt.type === 'tool_call') {
      upsertStreamingToolBubble(evt.name, null);
    } else if (evt.type === 'tool_result') {
      upsertStreamingToolBubble(evt.name, evt.ok !== false);
    } else if (evt.type === 'token') {
      appendStreamingToken(evt.content || '', evt.fragments || 1);
    } else if (evt.type === 'token_rollback') {
      rollbackStreamingTokens();
    }
    return;
  }
  if (msg.type === 'hubOllamaResult') {
    if (msg.requestId && msg.requestId !== activeAiRequestId) return;
    hideOllamaTypingIndicator();
    finalizeStreamingToolBubbles();
    setOllamaBusy(false);
    activeAiRequestId = '';
    if (msg.cancelled) {
      const streamingBubble = document.querySelector('[data-streaming-response="true"]');
      const contentEl = streamingBubble?.querySelector('.ollama-chat-content');
      const streamedText = String(contentEl?.textContent || '').trim();
      if (streamedText) {
        finalizeStreamingResponseBubbles();
        completeOllamaConversationRevision();
        pushOllamaMessage('assistant', streamedText, msg.model);
      } else {
        rollbackStreamingTokens();
        restoreOllamaConversationRevision();
      }
      _streamingResponseLocked = true;
      setOllamaStatus('■ Génération arrêtée.');
      return;
    }
    if (!msg.ok) {
      rollbackStreamingTokens();
      _streamingResponseLocked = true;
      setOllamaStatus(msg.error || 'Échec de la requête Ollama.', true);
      if (!restoreOllamaConversationRevision()) {
        pushOllamaMessage('system', msg.error || 'Échec de la requête Ollama.');
      }
      return;
    }
    if (msg.model) {
      rememberOllamaModel(msg.model, true);
    }
    const usage = normalizeOllamaUsage(msg.usage);
    const tokenLabel = usage.completionTokens
      ? ` · ${formatOllamaTokenCount(usage.completionTokens)} tokens générés`
      : '';
    setOllamaStatus(
      `✓ Terminé · ${msg.model || 'modèle inconnu'}${tokenLabel}`,
    );
    document.querySelectorAll('[data-ollama-status="true"]').forEach((el) => {
      el.title = usage.requestTotalTokens
        ? `${formatOllamaTokenCount(usage.requestTotalTokens)} tokens consommés pour la requête`
        : '';
    });
    // Let the pending animation frame paint, then persist the backend's complete
    // response as the source of truth. The streamed DOM is only a live preview.
    queueOrHandleOllamaResult(() => {
      const streamingBubble = document.querySelector('[data-streaming-response="true"]');
      const contentEl = streamingBubble?.querySelector('.ollama-chat-content');
      const streamedText = contentEl ? contentEl.textContent : '';
      finalizeStreamingResponseBubbles();
      completeOllamaConversationRevision();
      pushOllamaMessage(
        'assistant',
        msg.output || streamedText || '(Réponse vide)',
        msg.model,
        { usage },
      );
    });
    return;
  }
  if (msg.type === 'hubAnnotations') {
    if (isStaleStaticBinaryResponse(msg, 'static-annotations')) return;
    const annotations = msg.annotations || {};
    window._annotations = annotations;
    window.annotationFunctionAddrs = new Set();
    mergeAnnotationFunctionAddrs(msg.functionAddrs);
    refreshDisasmForAnnotations(msg.binaryPath, annotations);
    if (typeof populateDecompileSelect === 'function') {
      populateDecompileSelect(window.symbolsCache || []);
    }
    if (!renderAnnotationsList(annotations)) {
      renderBookmarks();
      updateActiveContextBars(window._lastDisasmAddr);
      updateDisasmSessionSummary();
      return;
    }
    renderBookmarks();
    updateActiveContextBars(window._lastDisasmAddr);
    updateDisasmSessionSummary();
    return;
  }
  if (msg.type === 'hubDisasmReady' && msg.binaryPath) {
    if (isStaleStaticBinaryResponse(msg, 'static-disasm-ready')) return;
    // Ce build a baké l'état courant des annotations : le prochain
    // hubAnnotations (toujours rechargé après hubSetBinaryPath) adoptera la
    // signature au lieu de déclencher un rebuild annotation-overlay inutile.
    window._adoptAnnotationDisasmSignatureFor = msg.binaryPath.trim();
    tabDataCache.disasm = { binaryPath: msg.binaryPath.trim() };
    tabDataCache.callgraph = null;
    tabDataCache.cfg = null;
    mergeAnnotationFunctionAddrs(msg.functionAddrs);
    renderAnnotationsList();
    if (msg.arch && typeof msg.arch === 'object') {
      currentArchSupport = msg.arch;
      // rAF : s'assure que showGroup (éventuel) a fini de reconstruire la barre
      requestAnimationFrame(_refreshArchSupportBadges);
    }
    // Si CFG ou call graph est actif, le recharger maintenant que le désassemblage est prêt
    const activeTab = typeof getActiveStaticTab === 'function' ? getActiveStaticTab() : '';
    if ((activeTab === 'cfg' || activeTab === 'callgraph') && typeof _autoLoadTab === 'function') {
      _autoLoadTab(activeTab);
    }
    return;
  }
  if (messageRouter?.handleMessage?.(msg)) {
    return;
  }
  if (msg.type === 'hubStaticCompileDone') {
    const btn = document.getElementById('btnCompileGcc');
    if (btn) { btn.disabled = false; btn.classList.remove('loading'); }
    return;
  }
  if (msg.type === 'compilerBrowseSourceResult') {
    if (msg.path) {
      const el = document.getElementById('gccSourcePath');
      if (el) { el.value = msg.path; el.dispatchEvent(new Event('input')); }
    }
    return;
  }
  if (msg.type === 'compilerBrowseOutputResult') {
    if (msg.path) {
      const el = document.getElementById('gccOutputPath');
      if (el) { el.value = msg.path; el.dispatchEvent(new Event('input')); }
    }
    return;
  }
  if (msg.type === 'compilerListResult') {
    window._compilerData = msg.compilers || [];
    if (typeof _applyCompilerAvailability === 'function') _applyCompilerAvailability(window._compilerData);
    return;
  }
  if (msg.type === 'compileResult') {
    const compileBtn = document.getElementById('btnCompileGcc');
    if (compileBtn) { compileBtn.disabled = false; compileBtn.classList.remove('loading'); }
    const el = document.getElementById('compile-result');
    if (!el) return;
    while (el.firstChild) el.removeChild(el.firstChild);
    if (msg.error || msg.exit_code !== 0) {
      el.style.cssText = 'margin-top:8px;padding:8px 10px;border-radius:3px;font-size:12px;line-height:1.6;background:var(--vscode-inputValidation-errorBackground,rgba(200,50,50,.12));border-left:3px solid var(--vscode-charts-red,#f14c4c)';
      const errLabel = document.createElement('div');
      errLabel.style.fontWeight = 'bold';
      errLabel.textContent = msg.error ? 'Toolchain indisponible' : 'Erreur de compilation';
      const errBody = document.createElement('pre');
      errBody.style.cssText = 'margin:4px 0 0;white-space:pre-wrap;word-break:break-all;font-size:11px;opacity:.9';
      errBody.textContent = (msg.error || msg.stderr || 'erreur inconnue').trim();
      el.appendChild(errLabel);
      el.appendChild(errBody);
    } else {
      el.style.cssText = 'margin-top:8px;padding:8px 10px;border-radius:3px;font-size:12px;line-height:1.6;background:var(--vscode-inputValidation-infoBackground,rgba(0,122,204,.1));border-left:3px solid var(--vscode-charts-green,#89d185)';
      const filename = msg.output_path.split('/').pop();
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap';
      const label = document.createElement('span');
      label.style.cssText = 'font-weight:bold;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
      label.title = msg.output_path;
      label.textContent = '\u2713 ' + filename;
      const pathLine = document.createElement('div');
      pathLine.style.cssText = 'font-size:10px;opacity:.7;margin-top:2px;word-break:break-all;cursor:pointer';
      pathLine.title = 'Cliquer pour copier';
      pathLine.textContent = msg.output_path;
      pathLine.addEventListener('click', () => navigator.clipboard?.writeText(msg.output_path));
      const btn = document.createElement('button');
      btn.textContent = 'Analyser';
      btn.className = 'btn btn-primary btn-sm';
      btn.addEventListener('click', () => {
        vscode.postMessage({ type: 'hubUseBinaryPath', binaryPath: msg.output_path });
      });
      row.appendChild(label);
      row.appendChild(btn);
      el.appendChild(row);
      el.appendChild(pathLine);
    }
    return;
  }
  if (msg.type === 'symbols') {
    if (isStaleStaticBinaryResponse(msg, 'dynamic-symbols')) return;
    const sel = document.getElementById('startSymbol');
    if (!sel) return;
    const preferred = 'main';
    const syms = Array.isArray(msg.symbols) && msg.symbols.length ? msg.symbols : [preferred];
    const cur = sel.value;
    sel.innerHTML = '';
    syms.forEach((s) => {
      const o = document.createElement('option');
      o.value = s;
      o.textContent = s;
      if (s === cur) o.selected = true;
      sel.appendChild(o);
    });
    if (!syms.includes(cur) && syms.length) {
      sel.value = syms.includes(preferred) ? preferred : syms[0];
    }
    return;
  }
  if (msg.type === 'generatedFiles') {
    const data = msg.files;
    if (!data || typeof data !== 'object') return;
    const fmt = (n) => n >= 1024 * 1024 ? `${(n / (1024 * 1024)).toFixed(1)} Mo` : n >= 1024 ? `${(n / 1024).toFixed(1)} Ko` : `${n} o`;
    const artifactLabels = {
      disasm: { title: 'Désassemblage texte', short: 'ASM', note: 'Vue assembleur exportée pour la navigation.' },
      mapping: { title: 'Index de navigation', short: 'IDX', note: 'Associe les lignes du désassemblage aux adresses et offsets.' },
      symbols: { title: 'Table des symboles', short: 'SYM', note: 'Symboles résolus et métadonnées utiles au hub.' },
      trace: { title: 'Trace d’exécution', short: 'TRC', note: 'Résultat dynamique ou export intermédiaire.' },
      input: { title: 'Entrée compilateur', short: 'SRC', note: 'Fichier source temporaire utilisé pour une compilation.' },
      artifact: { title: 'Artifact technique', short: 'FILE', note: 'Fichier intermédiaire conservé pour le workspace.' },
    };
    const cacheTypeLabels = {
      info: 'Infos binaire',
      sections: 'Sections',
      strings: 'Strings',
      symbols: 'Symboles',
      cfg: 'CFG',
      callgraph: 'Call graph',
      discovered: 'Fonctions',
      imports: 'Imports',
      decompile: 'Décompilation',
    };
    const cacheTypeShortLabels = {
      info: 'INFO',
      sections: 'SECT',
      strings: 'STR',
      symbols: 'SYM',
      cfg: 'CFG',
      callgraph: 'CG',
      discovered: 'FUNC',
      imports: 'IMP',
      decompile: 'DEC',
    };
    const cacheStatusBadge = (entry) => {
      const status = String(entry?.status || '').toLowerCase();
      if (status === 'ok') return '<span class="status-ok">OK</span>';
      if (status === 'stale') return '<span class="status-stale">À recalculer</span>';
      return '<span class="status-stale">Introuvable</span>';
    };
    const artifacts = Array.isArray(data.artifacts) ? data.artifacts : [];
    const cache = Array.isArray(data.cache) ? data.cache : [];
    const staleCount = Array.isArray(data.staleCache) ? data.staleCache.length : 0;
    const fileNameOnly = (value) => String(value || '').split(/[/\\]/).pop() || '—';
    const detailBlock = (label, valueHtml) => `
      <div class="files-detail-block">
        <span class="files-detail-label">${escapeHtml(label)}</span>
        <div class="files-detail-value">${valueHtml}</div>
      </div>
    `;
    const renderArtifactEntry = (artifact) => {
      const kind = artifactLabels[String(artifact.type || '').trim()] || artifactLabels.artifact;
      const binaryName = artifact.binary ? fileNameOnly(artifact.binary) : '';
      return `
        <details class="files-entry">
          <summary class="files-entry-summary">
            <div class="files-entry-main">
              <span class="files-entry-icon">${escapeHtml(kind.short || 'FILE')}</span>
              <div class="files-entry-copy">
                <span class="files-entry-title">${escapeHtml(kind.title)}</span>
                <span class="files-entry-subtitle">${escapeHtml(artifact.name || '—')}${binaryName ? ` · lié à ${escapeHtml(binaryName)}` : ''}</span>
              </div>
            </div>
            <div class="files-entry-meta">
              <span class="files-inline-tag">session</span>
              <span class="files-entry-size">${fmt(artifact.size || 0)}</span>
            </div>
            <span class="files-entry-toggle" aria-hidden="true"></span>
          </summary>
          <div class="files-entry-body">
            <div class="files-entry-detail-grid">
              ${detailBlock('Nom de fichier', `<code>${escapeHtml(artifact.name || '—')}</code>`)}
              ${detailBlock('Binaire lié', artifact.binary ? `<code title="${escapeHtml(artifact.binary)}">${escapeHtml(binaryName)}</code>` : '—')}
              ${detailBlock('Rôle', escapeHtml(kind.title))}
              ${detailBlock('Taille', escapeHtml(fmt(artifact.size || 0)))}
            </div>
            <div class="files-detail-note">${escapeHtml(kind.note)}</div>
          </div>
        </details>
      `;
    };
    const renderCacheEntry = (entry) => {
      const cacheTypes = Array.isArray(entry.cacheTypes) ? entry.cacheTypes : [];
      const cacheTypesLabel = cacheTypes.length === 1 ? '1 vue conservée' : `${cacheTypes.length} vues conservées`;
      const primaryType = cacheTypes[0] || '';
      const status = String(entry.status || '').toLowerCase();
      const summaryNote = status === 'ok'
        ? 'Réutilisable au prochain chargement.'
        : 'Cette entrée devra être recalculée avant réutilisation.';
      return `
        <details class="files-entry"${status !== 'ok' ? ' open' : ''}>
          <summary class="files-entry-summary">
            <div class="files-entry-main">
              <span class="files-entry-icon is-cache">${escapeHtml(cacheTypeShortLabels[primaryType] || 'CACHE')}</span>
              <div class="files-entry-copy">
                <span class="files-entry-title">${escapeHtml(fileNameOnly(entry.binaryPath || ''))}</span>
                <span class="files-entry-subtitle">${escapeHtml(cacheTypesLabel)} · cache ${escapeHtml(entry.key || '—')}</span>
              </div>
            </div>
            <div class="files-entry-meta">
              ${cacheStatusBadge(entry)}
              <span class="files-entry-size">${fmt(entry.size || 0)}</span>
            </div>
            <span class="files-entry-toggle" aria-hidden="true"></span>
          </summary>
          <div class="files-entry-body">
            <div class="files-entry-detail-grid">
              ${detailBlock('Binaire', entry.binaryPath ? `<code title="${escapeHtml(entry.binaryPath)}">${escapeHtml(fileNameOnly(entry.binaryPath))}</code>` : '—')}
              ${detailBlock('Identifiant', `<code>${escapeHtml(entry.key || '—')}</code>`)}
              ${detailBlock('Statut', cacheStatusBadge(entry))}
              ${detailBlock('Taille', escapeHtml(fmt(entry.size || 0)))}
              ${detailBlock('Vues conservées', cacheTypes.length
                ? `<div class="files-inline-tags">${cacheTypes.map((typeName) => `<span class="files-inline-tag">${escapeHtml(cacheTypeLabels[typeName] || typeName)}</span>`).join('')}</div>`
                : '—')}
            </div>
            <div class="files-detail-note">${escapeHtml(summaryNote)}</div>
          </div>
        </details>
      `;
    };
    const summaryGrid = document.getElementById('filesSummaryGrid');
    if (summaryGrid) {
      const cards = [
        { label: 'Entrées suivies', value: String(artifacts.length + cache.length), extra: 'artifacts + caches' },
        { label: 'Poids total', value: fmt(data.totalSize || 0), extra: 'dans .pile-ou-face', className: 'is-accent' },
        { label: 'Artifacts', value: String(artifacts.length), extra: 'session et exports' },
        { label: 'Caches à revoir', value: String(staleCount), extra: staleCount ? 'binaire modifié ou introuvable' : 'aucune entrée obsolète', className: staleCount ? 'is-stale' : '' },
      ];
      summaryGrid.innerHTML = cards
        .map((card) => `
          <div class="files-summary-card${card.className ? ` ${card.className}` : ''}">
            <span class="files-summary-label">${escapeHtml(card.label)}</span>
            <strong>${escapeHtml(card.value)}</strong>
            <span class="files-cell-subtle">${escapeHtml(card.extra)}</span>
          </div>
        `)
        .join('');
    }
    const artifactsCountEl = document.getElementById('filesArtifactsCount');
    if (artifactsCountEl) artifactsCountEl.textContent = String(artifacts.length);
    const cacheCountEl = document.getElementById('filesCacheCount');
    if (cacheCountEl) cacheCountEl.textContent = String(cache.length);
    const artifactsEl = document.getElementById('filesArtifacts');
    if (artifactsEl) {
      if (artifacts.length === 0) {
        artifactsEl.innerHTML = '<div class="files-empty"><p class="hint empty-state">Aucun artifact généré pour ce workspace.</p></div>';
      } else {
        artifactsEl.innerHTML = artifacts.map(renderArtifactEntry).join('');
      }
    }
    const cacheEl = document.getElementById('filesCache');
    if (cacheEl) {
      if (cache.length === 0) {
        cacheEl.innerHTML = '<div class="files-empty"><p class="hint empty-state">Aucune entrée de cache persistante pour le moment.</p></div>';
      } else {
        cacheEl.innerHTML = `${cache.map(renderCacheEntry).join('')}<p class="hint files-footnote">Les entrées “À recalculer” correspondent à un binaire modifié, supprimé ou à un cache devenu incohérent.</p>`;
      }
    }
    return;
  }
  if (msg.type === 'refreshGeneratedFiles') {
    vscode.postMessage({ type: 'listGeneratedFiles' });
    return;
  }
  // ── Import xrefs panel (inline sous importsContent) ─────────────────────
  function _showImportXrefsPanel(fnName, callsites, error) {
    let panel = document.getElementById('importXrefsPanel');
    if (!panel) {
      panel = document.createElement('div');
      panel.id = 'importXrefsPanel';
      panel.className = 'modern-card';
      panel.style.cssText = 'margin-top:10px;';
      const container = document.getElementById('importsContent');
      if (container) container.appendChild(panel);
    }
    panel.replaceChildren();

    const header = document.createElement('div');
    header.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:6px;';
    const title = document.createElement('span');
    title.className = 'section-label';
    title.textContent = `Xrefs → ${fnName || ''}`;
    const closeBtn = document.createElement('button');
    closeBtn.className = 'btn btn-sm';
    closeBtn.textContent = '✕';
    closeBtn.style.marginLeft = 'auto';
    closeBtn.addEventListener('click', () => panel.remove());
    header.append(title, closeBtn);
    panel.appendChild(header);

    if (!callsites) {
      // Loading state
      const p = document.createElement('p');
      p.className = 'hint';
      p.textContent = 'Recherche des callsites…';
      panel.appendChild(p);
      return;
    }
    if (error) {
      const p = document.createElement('p');
      p.className = 'hint error';
      p.textContent = error;
      panel.appendChild(p);
      return;
    }
    if (callsites.length === 0) {
      const p = document.createElement('p');
      p.className = 'hint';
      p.textContent = 'Aucun callsite trouvé (binaire strippé ou PLT non résolu).';
      panel.appendChild(p);
      return;
    }

    const table = document.createElement('table');
    table.className = 'data-table';
    const thead = table.createTHead();
    const hr = thead.insertRow();
    ['Adresse', 'Instruction'].forEach(t => {
      const th = document.createElement('th');
      th.textContent = t;
      hr.appendChild(th);
    });
    const tbody = table.createTBody();
    for (const cs of callsites) {
      const row = tbody.insertRow();
      row.className = 'nav-addr-row';
      row.dataset.addr = cs.addr || '';
      row.dataset.addrMatch = 'exact';
      const tdAddr = row.insertCell();
      const addrLink = document.createElement('a');
      addrLink.className = 'addr-link';
      addrLink.href = '#';
      addrLink.textContent = cs.addr || '?';
      addrLink.addEventListener('click', (e) => {
        e.preventDefault();
        const bp = getStaticBinaryPath();
        if (!bp) return;
        vscode.postMessage({ type: 'hubGoToAddress', binaryPath: bp, addr: cs.addr });
      });
      tdAddr.appendChild(addrLink);
      const tdText = row.insertCell();
      const code = document.createElement('code');
      code.style.fontSize = '11px';
      // Afficher la partie mnemonic + operands seulement (sans les bytes hex)
      const textParts = (cs.text || '').split(/\s{2,}/);
      code.textContent = textParts.length > 1 ? textParts.slice(1).join(' ').trim() : cs.text;
      tdText.appendChild(code);
    }
    panel.appendChild(table);
    updateActiveNavRows(window._lastDisasmAddr);
  }

  if (msg.type === 'hubImportsDone') {
    if (isStaleStaticBinaryResponse(msg, 'static-imports')) return;
    const renderStarted = performance.now();
    tabDataCache.imports = { binaryPath: getStaticBinaryPath() };
    const container = document.getElementById('importsContent');
    if (!container) return;
    const data = msg.data || {};
    if (data.error) {
      const p = document.createElement('p');
      p.className = 'hint error';
      p.textContent = data.error;
      container.replaceChildren(p);
      reportStaticWebviewPerf('imports.render', renderStarted, { error: true });
      return;
    }

    const imports = data.imports || [];
    const suspicious = data.suspicious || [];
    const score = data.score ?? 0;
    const totalFns = imports.reduce((n, d) => n + (d.functions || []).length, 0);

    const _CAT_COLOR = {
      INJECTION: 'var(--accent-red)', SHELLCODE: 'var(--accent-red)',
      EXECUTION: 'var(--accent-orange)', ANTI_DEBUG: '#b48ead',
      NETWORK: '#88c0d0', EVASION: 'var(--accent-orange)',
      PERSISTENCE: 'var(--accent-orange)', CRYPTO: 'var(--accent-blue-soft)',
    };
    const root = document.createDocumentFragment();

    // ── Score bar ──────────────────────────────────────────────────────────
    const scoreCard = document.createElement('div');
    scoreCard.className = 'modern-card';
    scoreCard.style.cssText = 'margin-bottom:10px;display:flex;align-items:center;gap:12px';
    const scoreLabel = document.createElement('span');
    scoreLabel.className = 'hint';
    scoreLabel.textContent = 'Score de suspicion';
    const scoreVal = document.createElement('span');
    scoreVal.style.cssText = `font-size:18px;font-weight:700;color:${score >= 60 ? 'var(--accent-red)' : score >= 30 ? 'var(--accent-orange)' : 'var(--accent-blue-soft)'}`;
    scoreVal.textContent = `${score}/100`;
    const scoreDetail = document.createElement('span');
    scoreDetail.className = 'hint';
    scoreDetail.textContent = `${suspicious.length} import(s) suspect(s) sur ${totalFns}`;
    scoreCard.append(scoreLabel, scoreVal, scoreDetail);
    root.appendChild(scoreCard);

    if (imports.length === 0) {
      const p = document.createElement('p');
      p.className = 'hint';
      p.textContent = 'Aucun import détecté (binaire statiquement lié ou strippé).';
      root.appendChild(p);
      container.replaceChildren(root);
      reportStaticWebviewPerf('imports.render', renderStarted, {
        dlls: imports.length,
        suspicious: suspicious.length,
        functions: totalFns,
        empty: true,
      });
      return;
    }

    // ── Imports suspects ───────────────────────────────────────────────────
    if (suspicious.length > 0) {
      const h = document.createElement('h4');
      h.className = 'section-label';
      h.style.margin = '10px 0 6px';
      h.textContent = 'Imports suspects';
      root.appendChild(h);

      const table = document.createElement('table');
      table.className = 'data-table';
      const thead = table.createTHead();
      const hr = thead.insertRow();
      ['Fonction', 'DLL', 'Catégorie', 'Description'].forEach(t => {
        const th = document.createElement('th');
        th.textContent = t;
        hr.appendChild(th);
      });
      const tbody = table.createTBody();
      for (const s of suspicious) {
        const row = tbody.insertRow();
        const tdFn = row.insertCell(); tdFn.appendChild(Object.assign(document.createElement('code'), { textContent: s.function }));
        const tdDll = row.insertCell(); tdDll.className = 'hint'; tdDll.textContent = s.dll;
        const tdCat = row.insertCell();
        const badge = document.createElement('span');
        badge.style.cssText = `color:${_CAT_COLOR[s.category] || 'var(--text-muted)'};font-weight:600;font-size:10px`;
        badge.textContent = s.category;
        tdCat.appendChild(badge);
        const tdDesc = row.insertCell(); tdDesc.style.fontSize = '11px'; tdDesc.textContent = s.description;
      }
      root.appendChild(table);
    }

    // ── Imports par DLL ────────────────────────────────────────────────────
    const h2 = document.createElement('h4');
    h2.className = 'section-label';
    h2.style.margin = '10px 0 6px';
    h2.textContent = `Tous les imports (${imports.length} DLL / bibliothèque(s))`;
    root.appendChild(h2);

    const suspSet = new Set(suspicious.map(s => s.function));
    for (const dll of imports) {
      const details = document.createElement('details');
      details.className = 'imports-dll-group';
      const summary = document.createElement('summary');
      const dllName = document.createElement('span');
      dllName.className = 'imports-dll-name';
      dllName.textContent = dll.dll;
      const dllCount = document.createElement('span');
      dllCount.className = 'imports-dll-count';
      dllCount.textContent = ` ${dll.count} fonction(s)`;
      summary.append(dllName, dllCount);
      details.appendChild(summary);
      const fnsDiv = document.createElement('div');
      fnsDiv.className = 'imports-dll-fns';
      for (const fn of (dll.functions || [])) {
        const btn = document.createElement('button');
        btn.className = 'imports-fn-btn' + (suspSet.has(fn) ? ' suspicious' : '');
        btn.textContent = fn;
        btn.title = 'Voir les callsites (xrefs)';
        btn.addEventListener('click', () => {
          const bp = getStaticBinaryPath();
          if (!bp) return;
          _showImportXrefsPanel(fn);
          vscode.postMessage({ type: 'hubLoadImportXrefs', binaryPath: bp, fnName: fn });
        });
        fnsDiv.appendChild(btn);
      }
      details.appendChild(fnsDiv);
      root.appendChild(details);
    }

    container.replaceChildren(root);
    reportStaticWebviewPerf('imports.render', renderStarted, {
      dlls: imports.length,
      suspicious: suspicious.length,
      functions: totalFns,
      score,
    });
    return;
  }
  if (msg.type === 'hubExportsDone') {
    if (isStaleStaticBinaryResponse(msg, 'static-exports')) return;
    const renderStarted = performance.now();
    const container = document.getElementById('exportsContent');
    if (!container) return;
    const data = msg.data || {};
    container.replaceChildren();
    const hdr = document.createElement('div');
    hdr.className = 'section-label';
    hdr.style.cssText = 'margin-bottom:8px;';
    hdr.textContent = `Exports (${data.count ?? 0})`;
    container.appendChild(hdr);
    if (data.error) {
      const p = document.createElement('p'); p.className = 'hint error'; p.textContent = data.error;
      container.appendChild(p);
      reportStaticWebviewPerf('exports.render', renderStarted, { error: true, count: Number(data.count || 0) });
      return;
    }
    const exports = data.exports || [];
    if (exports.length === 0) {
      const p = document.createElement('p'); p.className = 'hint'; p.textContent = 'Aucun export trouvé.';
      container.appendChild(p);
      reportStaticWebviewPerf('exports.render', renderStarted, { count: 0, empty: true });
      return;
    }
    const table = document.createElement('table');
    table.className = 'data-table';
    const thead = table.createTHead();
    const hr = thead.insertRow();
    ['Adresse', 'Nom', 'Type'].forEach(t => {
      const th = document.createElement('th'); th.textContent = t; hr.appendChild(th);
    });
    const tbody = table.createTBody();
    for (const exp of exports) {
      const row = tbody.insertRow();
      row.className = 'nav-addr-row';
      row.dataset.addr = exp.addr || '';
      row.dataset.addrMatch = 'function';
      const tdAddr = row.insertCell();
      const addrLink = document.createElement('a');
      addrLink.className = 'addr-link'; addrLink.href = '#';
      addrLink.textContent = exp.addr || '?';
      addrLink.title = 'Aller au désassemblage';
      addrLink.addEventListener('click', (e) => {
        e.preventDefault();
        const bp = getStaticBinaryPath();
        if (bp) { vscode.postMessage({ type: 'hubGoToAddress', addr: exp.addr, binaryPath: bp }); }
      });
      tdAddr.appendChild(addrLink);
      const tdName = row.insertCell();
      tdName.style.fontFamily = 'var(--font-mono)';
      tdName.style.fontSize = '11px';
      if (exp.demangled) {
        const span = document.createElement('span');
        span.textContent = exp.demangled;
        span.title = exp.name;
        tdName.appendChild(span);
        const raw = document.createElement('span');
        raw.className = 'hint'; raw.style.marginLeft = '6px'; raw.textContent = `(${exp.name})`;
        tdName.appendChild(raw);
      } else {
        tdName.textContent = exp.name || '?';
      }
      const tdType = row.insertCell();
      const badge = document.createElement('span');
      badge.className = `imports-cat-badge imports-cat-${exp.type === 'data' ? 'data' : 'function'}`;
      badge.textContent = exp.type || 'fn';
      tdType.appendChild(badge);
      if (exp.ordinal != null) {
        const ord = document.createElement('span');
        ord.className = 'hint'; ord.style.marginLeft = '6px'; ord.textContent = `#${exp.ordinal}`;
        tdType.appendChild(ord);
      }
    }
    container.appendChild(table);
    updateActiveNavRows(window._lastDisasmAddr);
    reportStaticWebviewPerf('exports.render', renderStarted, { count: exports.length });
    return;
  }
  if (msg.type === 'hubImportXrefsDone') {
    if (isStaleStaticBinaryResponse(msg, 'static-import-xrefs')) return;
    const data = msg.data || {};
    _showImportXrefsPanel(data.function, data.callsites || [], data.error);
    return;
  }
  if (msg.type === 'hubSymbols') {
    if (isStaleStaticBinaryResponse(msg, 'static-symbols')) return;
    const renderStarted = performance.now();
    tabDataCache.symbols = { binaryPath: getStaticBinaryPath() };
    const syms = msg.symbols || [];
    window.symbolsCache = syms;
    const navSel = document.getElementById('navSymbolSelect');
    if (navSel) {
      const cur = navSel.value;
      navSel.innerHTML = '<option value="">Autre symbole…</option>' +
        syms.filter(s => s.type === 'F' || s.type === 'T' || s.type === 'f' || s.type === 't')
          .slice(0, 50)
          .map(s => `<option value="${escapeHtml(s.name)}">${escapeHtml(s.name)} @ ${escapeHtml(s.addr)}</option>`).join('');
      if (cur && syms.some(s => s.name === cur)) navSel.value = cur;
    }
    const container = document.getElementById('symbolsContent');
    if (!container) return;
    const rows = syms.map(s => {
      const addrNum = parseInt((s.addr || '').trim(), 16);
      const isNavigable = !isNaN(addrNum) && addrNum > 0x1000;
      const addrCell = isNavigable
        ? `<code class="addr-link" data-addr="${escapeHtml(s.addr)}" style="cursor:pointer">${escapeHtml(s.addr)}</code>`
        : `<code class="addr-dim">${escapeHtml(s.addr)}</code>`;
      return `<tr class="nav-addr-row" data-addr="${escapeHtml(s.addr)}" data-addr-match="function"><td>${addrCell}</td><td>${escapeHtml(s.type)}</td><td><code>${escapeHtml(s.name)}</code></td></tr>`;
    }).join('');
    container.innerHTML = `<table class="data-table"><thead><tr><th>Adresse</th><th>Type</th><th>Nom</th></tr></thead><tbody>${rows}</tbody></table><p class="hint">Clic sur une adresse → aller au désassemblage.</p>`;
    container.querySelectorAll('.addr-link').forEach(el => {
      el.style.cursor = 'pointer';
      el.addEventListener('click', () => { const a = el.dataset.addr; if (a) vscode.postMessage({ type: 'hubGoToAddress', addr: a, binaryPath: getStaticBinaryPath() }); });
    });
    updateActiveNavRows(window._lastDisasmAddr);
    populateDecompileSelect(syms);
    updateActiveContextBars(window._lastDisasmAddr);
    if (isStaticTabActive('decompile')) {
      const selectedAddr = document.getElementById('decompileAddrSelect')?.value || '';
      if ((decompileUiState.renderedAddr || '') !== selectedAddr) requestDecompileForCurrentSelection();
    }
    if (loadAllPending > 0) { loadAllPending--; if (loadAllPending <= 0) { const b = document.getElementById('btnLoadAll'); if (b) { b.disabled = false; b.classList.remove('loading'); } } }
    reportStaticWebviewPerf('symbols.render', renderStarted, {
      symbols: syms.length,
      rowsRendered: container.querySelectorAll('tbody tr').length,
    });
    return;
  }
  if (msg.type === 'hubStrings') {
    if (isStaleStaticBinaryResponse(msg, 'static-strings')) return;
    const currentBinaryPath = getStaticBinaryPath();
    const responseBinaryPath = String(msg.binaryPath || '').trim();
    tabDataCache.strings = { binaryPath: currentBinaryPath };
    const container = document.getElementById('stringsContent');
    if (!container) return;
    const allStrings = msg.strings || [];
    stringsCache = allStrings;
    stringsPage = 1;
    renderStringsTable(container, allStrings, '', false);
    window.reportPofWebviewPerf?.('strings.message.received', {
      strings: Array.isArray(allStrings) ? allStrings.length : 0,
      binaryPath: responseBinaryPath || currentBinaryPath,
    }, { afterPaint: true });

    if (loadAllPending > 0) { loadAllPending--; if (loadAllPending <= 0) { const b = document.getElementById('btnLoadAll'); if (b) { b.disabled = false; b.classList.remove('loading'); } } }
    return;
  }
  if (msg.type === 'hubPayloadHex') {
    const el = document.getElementById('payloadHexResult');
    const countEl = document.getElementById('payloadByteCount');
    if (el) {
      el.textContent = msg.error || msg.hex || '—';
      el.classList.toggle('error', !!msg.error);
    }
    if (countEl && msg.hex && !msg.error) {
      const len = msg.hex.length / 2;
      countEl.textContent = `(${len} octet${len > 1 ? 's' : ''})`;
    } else if (countEl) countEl.textContent = '';
    return;
  }
  if (msg.type === 'hubAutoFromCmpResult') {
    const hint = document.getElementById('exploitAutoHint');
    if (msg.error) {
      if (hint) hint.textContent = `Auto CMP: ${msg.error}`;
      vscode.postMessage({ type: 'hubError', message: msg.error });
      return;
    }

    const startSymbol = document.getElementById('exploitStartSymbol')?.value?.trim() || 'main';
    const targetSymbol = document.getElementById('exploitTargetSymbol')?.value?.trim() || 'win';
    const payloadTarget = document.getElementById('exploitPayloadTarget')?.value || 'argv1';
    const maxSteps = document.getElementById('exploitMaxSteps')?.value?.trim() || '400';

    if (typeof msg.padding === 'number' && Number.isFinite(msg.padding) && msg.padding > 0) {
      const exploitBufferSize = document.getElementById('exploitBufferSize');
      if (exploitBufferSize) exploitBufferSize.value = String(msg.padding);
    }
    if (typeof msg.suffix === 'string' && msg.suffix.length > 0) {
      const suffixInput = document.getElementById('exploitPayloadSuffix');
      if (suffixInput) suffixInput.value = msg.suffix;
    }

    const payloadExpr = String(msg.payloadExpr || '').trim();
    if (!payloadExpr) {
      if (hint) hint.textContent = 'Auto CMP: payload non généré.';
      return;
    }

    applyDynamicPreset({
      startSymbol,
      targetSymbol,
      payloadExpr,
      payloadTarget,
      maxSteps,
      suggestedOffset: msg.captureBufferOffset ?? -96,
      suggestedCaptureSize: msg.captureBufferSize ?? 128,
      binaryPath: getStaticBinaryPath()
    });

    if (hint) {
      const details = [];
      if (typeof msg.bufferOffset === 'number') details.push(`buffer=${msg.bufferOffset}`);
      if (typeof msg.varOffset === 'number') details.push(`cmpVar=${msg.varOffset}`);
      if (typeof msg.padding === 'number') details.push(`padding=${msg.padding}`);
      hint.textContent = `Auto CMP OK: ${payloadExpr}${details.length ? ` (${details.join(', ')})` : ''}`;
    }
    return;
  }
  if (msg.type === 'hubXrefs') {
    if (isStaleStaticBinaryResponse(msg, 'static-xrefs')) return;
    const renderStarted = performance.now();
    if (msg.requestKey && typeof _pendingXrefRequests !== 'undefined' && _pendingXrefRequests.has(msg.requestKey)) {
      const pending = _pendingXrefRequests.get(msg.requestKey);
      _pendingXrefRequests.delete(msg.requestKey);
      clearTimeout(pending.timeoutId);
      pending.resolve({
        refs: Array.isArray(msg.refs) ? msg.refs : [],
        targets: Array.isArray(msg.targets) ? msg.targets : [],
        addr: msg.addr || '',
        mode: msg.mode || 'to',
        error: msg.error || '',
      });
    }
    const el = document.getElementById('xrefsResult');
    const contentEl = document.getElementById('xrefsResultContent');
    if (!el) return;
    const refs = msg.refs || [];
    const targets = msg.targets || [];
    const addr = msg.addr || '';
    const mode = msg.mode || 'to';
    const hasError = msg.error;
    window.xrefsCache = { refs, targets, addr, mode };
    el.style.display = 'block';
    el.classList.add('xrefs-panel-visible');
    const target = contentEl || el;
    const makeAddrLink = (a) => {
      const span = getKnownSpanLengthForAddress(a);
      return `<code class="addr-link" data-addr="${escapeHtml(a)}" data-span="${escapeHtml(String(span))}">${escapeHtml(a)}</code>`;
    };
    const makeJumpButton = (a, label = 'Ouvrir') => {
      const span = getKnownSpanLengthForAddress(a);
      return `<button type="button" class="xrefs-jump-btn" data-addr="${escapeHtml(a)}" data-span="${escapeHtml(String(span))}">${escapeHtml(label)}</button>`;
    };
    const renderStackHints = (hints) => {
      if (!Array.isArray(hints) || hints.length === 0) return '';
      const chips = hints.map(h => {
        const label = `${h.kind === 'arg' ? 'arg' : 'var'} ${h.name}`;
        const title = h.location ? `${label} @ ${h.location}` : label;
        return `<span class="xref-stack-chip" title="${escapeHtml(title)}">${escapeHtml(label)}</span>`;
      }).join('');
      return `<div class="xref-stack-hints">${chips}</div>`;
    };
    const renderTypedStructHints = (hints) => {
      if (!Array.isArray(hints) || hints.length === 0) return '';
      const chips = hints.map((hint) => {
        const label = hint.label || hint.addr || 'type';
        const typeKind = hint.struct_kind || hint.kind || 'struct';
        const title = [
          hint.struct_name ? `${typeKind} ${hint.struct_name}` : null,
          hint.field_name ? `champ ${hint.field_name}` : null,
          hint.field_type || null,
          hint.addr || null,
        ].filter(Boolean).join(' • ');
        return `<span class="xref-stack-chip" title="${escapeHtml(title)}">${escapeHtml(label)}</span>`;
      }).join('');
      return `<div class="xref-stack-hints">${chips}</div>`;
    };
    const bindAddrLinks = () => {
      target.querySelectorAll('.addr-link, .xrefs-jump-btn').forEach(link => {
        link.style.cursor = 'pointer';
        link.addEventListener('click', () => {
          const a = link.dataset.addr;
          const spanLength = normalizeSpanLength(link.dataset.span || 1);
          if (a) {
            document.getElementById('goToAddrInput').value = a;
            const badge = document.getElementById('annotationAddrBadge');
            if (badge) { badge.textContent = a; badge.dataset.addr = a; badge.classList.add('has-addr'); }
            const btn = document.getElementById('btnAddAnnotation');
            if (btn) btn.disabled = false;
            vscode.postMessage({ type: 'hubGoToAddress', addr: a, binaryPath: getStaticBinaryPath(), spanLength });
          }
        });
      });
      target.querySelectorAll('.xrefs-fallback-btn[data-xref-open]').forEach((button) => {
        button.addEventListener('click', () => {
          const action = String(button.dataset.xrefOpen || '');
          const actionAddr = normalizeHexAddress(button.dataset.addr || addr || '');
          if (!actionAddr) return;
          if (action === 'strings') {
            openVulnStrings(actionAddr);
            return;
          }
          if (action === 'hex') {
            openVulnHex(actionAddr, '', getKnownSpanLengthForAddress(actionAddr));
          }
        });
      });
    };
    if (hasError) {
      target.innerHTML = `<p class="xrefs-msg xrefs-error">${escapeHtml(hasError)}</p>`;
    } else if (mode === 'from') {
      if (targets.length === 0) {
        target.innerHTML = `<p class="xrefs-msg">L'instruction à ${escapeHtml(addr)} ne référence aucune adresse (pas de jmp/call).</p>`;
      } else {
        const targetLinks = targets.map(t => makeAddrLink(t)).join(', ');
        const source = msg.source || null;
        const sourceMeta = source
          ? `<div class="xrefs-source-card">
              <div class="xrefs-source-head">
                <span class="xrefs-source-title">Source</span>
                ${source.function_name ? `<span class="xrefs-source-fn">${escapeHtml(source.function_name)}</span>` : ''}
                ${source.function_addr ? `<code>${escapeHtml(source.function_addr)}</code>` : ''}
              </div>
              <code class="xrefs-source-instr">${escapeHtml(source.text || '')}</code>
              ${renderStackHints(source.stack_hints)}
              ${renderTypedStructHints(source.typed_struct_hints)}
            </div>`
          : '';
        target.innerHTML = `
          <div class="xrefs-summary">
            <p class="xrefs-title">Références depuis ${escapeHtml(addr)}</p>
            <span class="xrefs-summary-count">${targets.length} cible${targets.length > 1 ? 's' : ''}</span>
          </div>
          <p class="xrefs-explain">Lecture : l'instruction sélectionnée pointe vers les adresses ci-dessous. Clique une cible pour ouvrir le désassemblage à cet endroit.</p>
          ${sourceMeta}
          <p class="xrefs-targets">Cible(s) : ${targetLinks}</p>`;
        bindAddrLinks();
      }
    } else {
      if (refs.length === 0) {
        target.innerHTML = buildDataXrefsEmptyState(addr);
        bindAddrLinks();
      } else {
        const rows = refs.map(r => {
          const fnCell = r.function_name
            ? `<div class="xref-function-name">${escapeHtml(r.function_name)}</div>${r.function_addr ? `<code class="xref-function-addr">${escapeHtml(r.function_addr)}</code>` : ''}`
            : '—';
          const instr = `<code>${escapeHtml((r.text || '').substring(0, 90))}</code>${renderStackHints(r.stack_hints)}${renderTypedStructHints(r.typed_struct_hints)}`;
          return `<tr><td>${makeAddrLink(r.from_addr)}</td><td>${fnCell}</td><td><span class="xref-type xref-${r.type}">${escapeHtml(r.type)}</span></td><td>${instr}</td><td class="xrefs-action-cell">${makeJumpButton(r.from_addr, 'Aller au call')}</td></tr>`;
        }).join('');
        target.innerHTML = `
          <div class="xrefs-summary">
            <p class="xrefs-title">Références vers ${escapeHtml(addr)}</p>
            <span class="xrefs-summary-count">${refs.length} callsite${refs.length > 1 ? 's' : ''}</span>
          </div>
          <p class="xrefs-explain">Lecture : l'adresse demandée est ciblée par les instructions listées. Dans ton exemple, les deux lignes <code>call 0x100004059</code> appellent cette même destination.</p>
          <div class="xrefs-table-wrap">
            <table class="data-table">
              <thead><tr><th>Depuis</th><th>Fonction</th><th>Type</th><th>Instruction</th><th>Action</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          </div>`;
        bindAddrLinks();
      }
    }
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    reportStaticWebviewPerf('xrefs.render', renderStarted, {
      refs: refs.length,
      targets: targets.length,
      mode,
      error: Boolean(hasError),
      addr,
    });
    return;
  }
  if (msg.type === 'hubBinaryInfo') {
    if (isStaleStaticBinaryResponse(msg, 'static-info')) return;
    const renderStarted = performance.now();
    tabDataCache.info = { binaryPath: getStaticBinaryPath() };
    const container = document.getElementById('infoContent');
    if (!container) return;
    const info = msg.info || {};
    if (info.error) {
      container.innerHTML = `<p class="hint error">${escapeHtml(info.error)}</p>`;
    } else {
      window.lastBinaryArch = info.arch || '';
      updateTopBarBinaryDisplay(getStaticBinaryPath(), getCurrentBinaryMeta(), info);
      const rows = [
        ['Format', info.format || '—'],
        ['Machine', info.machine || '—'],
        ['Entry point', info.entry || '—'],
        ['Type', info.type || '—'],
        ['Bits', info.bits ? info.bits + '-bit' : '—'],
        ['Endianness', info.endianness || '—'],
        ['Stripped', info.stripped || '—'],
        ['Arch (objdump)', info.arch || '—'],
        ['Interp', info.interp || '—']
      ].map(([k, v]) => `<div class="info-row"><span class="info-key">${escapeHtml(k)}</span><span class="info-val">${escapeHtml(String(v))}</span></div>`).join('');
      container.innerHTML = `<div class="info-grid">${rows}</div>`;
    }
    if (typeof resetDetectionStateForBinary === 'function') {
      resetDetectionStateForBinary(getStaticBinaryPath());
    }
    updateDisasmSessionSummary();
    if (loadAllPending > 0) { loadAllPending--; if (loadAllPending <= 0) { const b = document.getElementById('btnLoadAll'); if (b) { b.disabled = false; b.classList.remove('loading'); } } }
    reportStaticWebviewPerf('binary.info.render', renderStarted, {
      error: Boolean(info.error),
      format: String(info.format || ''),
      arch: String(info.arch || ''),
    });
    return;
  }
  if (msg.type === 'hubSections') {
    if (isStaleStaticBinaryResponse(msg, 'static-sections')) return;
    const renderStarted = performance.now();
    tabDataCache.sections = { binaryPath: getStaticBinaryPath() };
    const container = document.getElementById('sectionsContent');
    const secs = msg.sections || [];
    window.sectionsCache = secs;
    const err = msg.error;
    const bp = getStaticBinaryPath();

    // Mettre à jour le dropdown Section dans l'onglet Désassemblage
    const disasmSectionSel = document.getElementById('disasmSection');
    if (disasmSectionSel) {
      const cur = disasmSectionSel.value;
      disasmSectionSel.innerHTML = '<option value="">Toutes</option>' +
        secs.map(s => `<option value="${escapeHtml(s.name)}">${escapeHtml(s.name)} (${s.type || ''})</option>`).join('');
      if (cur && secs.some(s => s.name === cur)) disasmSectionSel.value = cur;
    }
    updateActiveContextBars(window._lastDisasmAddr);
    updateDisasmSessionSummary();

    if (!container) return;
    if (err) {
      container.innerHTML = `<p class="hint error">${escapeHtml(err)}</p>`;
    } else {
      const rows = secs.map(s => {
        const secName = escapeHtml(s.name);
        return `<tr class="section-row" data-section="${escapeHtml(s.name)}"><td>${s.idx}</td><td><code>${secName}</code></td><td><code>${escapeHtml(s.size_hex || s.size)}</code></td><td><code>${escapeHtml(s.vma_hex || s.vma)}</code></td><td>${escapeHtml(s.type || '')}</td></tr>`;
      }).join('');
      container.innerHTML = `<table class="data-table"><thead><tr><th>Idx</th><th>Nom</th><th>Taille</th><th>VMA</th><th>Type</th></tr></thead><tbody>${rows}</tbody></table><p class="hint">Clic sur une section → désassembler cette section (fichier séparé). Le désasm complet reste intact. ${secs.length} section(s).</p>`;
      container.querySelectorAll('.section-row').forEach((tr) => {
        tr.addEventListener('click', () => {
          const sec = tr.dataset.section;
          if (sec && bp) vscode.postMessage({ type: 'hubOpenDisasm', binaryPath: bp, section: sec });
        });
      });
    }
    if (loadAllPending > 0) { loadAllPending--; if (loadAllPending <= 0) { const b = document.getElementById('btnLoadAll'); if (b) { b.disabled = false; b.classList.remove('loading'); } } }
    reportStaticWebviewPerf('sections.render', renderStarted, {
      sections: secs.length,
      error: Boolean(err),
    });
    return;
  }
  if (msg.type === 'hubCfg') {
    if (isStaleStaticBinaryResponse(msg, 'static-cfg')) return;
    const renderStarted = performance.now();
    const container = document.getElementById('cfgContent');
    if (!container) return;
    const currentBinaryPath = getStaticBinaryPath() || '';
    const responseBinaryPath = String(msg.binaryPath || '').trim();
    tabDataCache.cfg = { binaryPath: responseBinaryPath || currentBinaryPath };
    const cfgState = getGraphUiState('cfg', currentBinaryPath);
    const functions = Array.isArray(msg.functions) ? msg.functions : [];
    const requestedFuncAddr = String(msg.funcAddr || '').trim();
    vscode.postMessage({
      type: 'hubDebugLog',
      scope: 'static-cfg',
      event: 'received',
      details: {
        currentBinaryPath,
        responseBinaryPath,
        requestedFuncAddr,
        functions: functions.length,
        blocks: Array.isArray(msg.cfg?.blocks) ? msg.cfg.blocks.length : 0,
        edges: Array.isArray(msg.cfg?.edges) ? msg.cfg.edges.length : 0,
      },
    });
    const activeFuncAddr = requestedFuncAddr && functions.some((fn) => String(fn.addr || '') === requestedFuncAddr)
      ? requestedFuncAddr
      : '';
    if (requestedFuncAddr && !activeFuncAddr && functions.length > 0 && currentBinaryPath) {
      if (typeof cfgUiState !== 'undefined') cfgUiState.funcAddr = '';
      tabDataCache.cfg = null;
      setStaticLoading('cfgContent', 'Chargement CFG…');
      postBinaryAwareMessage('hubLoadCfg', {
        binaryPath: currentBinaryPath,
        useCache: document.getElementById('useCache')?.checked !== false,
      });
      return;
    }
    // Sync funcAddr and populate function selector.
    if (typeof cfgUiState !== 'undefined') cfgUiState.funcAddr = activeFuncAddr;
    const funcSel = document.getElementById('cfgFuncSelect');
    if (funcSel && functions.length > 0) {
      while (funcSel.firstChild) funcSel.removeChild(funcSel.firstChild);
      const allOpt = document.createElement('option');
      allOpt.value = '';
      allOpt.textContent = '\u2014 D\u00e9sassemblage complet \u2014';
      funcSel.appendChild(allOpt);
      functions.forEach(fn => {
        const opt = document.createElement('option');
        opt.value = String(fn.addr);
        const instrInfo = fn.instrCount > 0 ? `  (${fn.instrCount} instr.)` : '';
        opt.textContent = `${fn.name}${instrInfo}`;
        if (fn.addr === activeFuncAddr) opt.selected = true;
        funcSel.appendChild(opt);
      });
    }
    const cfg = msg.cfg || { blocks: [], edges: [] };
    const blocks = cfg.blocks || [];
    const edges = cfg.edges || [];
    const isolateFocus = blocks.some((block) => block.addr === cfgState.isolateAddr) ? cfgState.isolateAddr : '';
    if (!isolateFocus) cfgState.isolateAddr = '';
    const isolateRadius = Number.isFinite(Number(cfgState.isolateRadius)) ? Number(cfgState.isolateRadius) : 1;
    const visibleAddrs = isolateFocus ? collectGraphNeighborhood(isolateFocus, edges, isolateRadius) : null;
    if (blocks.length === 0) {
      const bp = getStaticBinaryPath();
      const hint = bp ? 'Aucun bloc CFG détecté pour cette fonction.' : 'Sélectionnez d\'abord un binaire.';
      while (container.firstChild) container.removeChild(container.firstChild);
      const hintEl = document.createElement('p');
      hintEl.className = 'hint';
      hintEl.textContent = hint;
      container.appendChild(hintEl);
      if (!bp) {
        const btnSel = document.createElement('button');
        btnSel.type = 'button';
        btnSel.className = 'btn btn-primary';
        btnSel.textContent = 'Sélectionner un binaire';
        btnSel.addEventListener('click', () => vscode.postMessage({ type: 'requestBinarySelection' }));
        container.appendChild(btnSel);
      }
      reportStaticWebviewPerf('cfg.render', renderStarted, {
        blocks: 0,
        edges: edges.length,
        functions: functions.length,
        empty: true,
      });
      return;
    }
    const MAX_CFG_BLOCKS = 200;
    if (blocks.length > MAX_CFG_BLOCKS && !msg.funcAddr) {
      tabDataCache.cfg = null;
      while (container.firstChild) container.removeChild(container.firstChild);
      const warnEl = document.createElement('p');
      warnEl.className = 'hint';
      warnEl.textContent = `CFG trop large (${blocks.length} blocs). Sélectionnez une fonction dans le menu ci-dessus.`;
      container.appendChild(warnEl);
      reportStaticWebviewPerf('cfg.render', renderStarted, {
        blocks: blocks.length,
        edges: edges.length,
        functions: functions.length,
        tooLarge: true,
      });
      return;
    }
    // Table view — build with DOM API (no innerHTML with variables)
    const adj2 = window.cfgHelpers.buildAdjacency(edges);
    const tableEl = document.createElement('div');
    tableEl.className = 'cfg-table-view';
    const table = document.createElement('table');
    table.className = 'data-table';
    const thead = table.createTHead();
    const hrow = thead.insertRow();
    ['Bloc', 'Instr.', 'Suivants', 'Première instr.'].forEach(h => {
      const th = document.createElement('th');
      th.textContent = h;
      hrow.appendChild(th);
    });
    const tbody = table.createTBody();
    const rowEls = {};
    blocks.forEach(b => {
      const succs = (adj2[b.addr] || []).map(e => `${e.type}: ${e.to}`).join(', ') || '\u2014';
      const firstInstr = formatCfgLineDisplay((b.lines || [])[0], 82) || '';
      const row = tbody.insertRow();
      row.dataset.blockAddr = b.addr;
      rowEls[b.addr] = row;
      const td1 = row.insertCell();
      const addrCode = document.createElement('code');
      addrCode.className = 'addr-link';
      addrCode.dataset.addr = b.addr;
      addrCode.textContent = b.addr;
      addrCode.style.cursor = 'pointer';
      addrCode.addEventListener('click', (ev) => {
        ev.stopPropagation();
        syncCfgActiveAddress(b.addr, { reveal: isStaticTabActive('cfg') });
        vscode.postMessage({ type: 'hubGoToAddress', addr: b.addr, binaryPath: getStaticBinaryPath() });
      });
      td1.appendChild(addrCode);
      const incomingCaseSummary = summarizeSwitchCaseLabels(b.incoming_case_labels || [], { max: 2 });
      if (incomingCaseSummary) {
        const badge = document.createElement('span');
        badge.className = 'cfg-case-badge-inline';
        badge.textContent = incomingCaseSummary;
        badge.title = summarizeSwitchCaseLabels(b.incoming_case_labels || [], { max: 12 });
        td1.appendChild(document.createTextNode(' '));
        td1.appendChild(badge);
      }
      row.insertCell().textContent = (b.lines || []).length;
      const td3 = row.insertCell();
      const succsCode = document.createElement('code');
      succsCode.textContent = succs;
      td3.appendChild(succsCode);
      const td4 = row.insertCell();
      td4.title = firstInstr;
      td4.textContent = firstInstr + (firstInstr.length >= 50 ? '\u2026' : '');
    });
    const hintP = document.createElement('p');
    hintP.className = 'hint';
    hintP.textContent = `${blocks.length} bloc(s) \u2014 Clic sur une adresse \u2192 aller au d\u00e9sassemblage.`;
    tableEl.appendChild(table);
    tableEl.appendChild(hintP);
    // Graph view using renderGraphSvg
    const zoomState = { scale: 1 };
    const graphBlocks = visibleAddrs ? blocks.filter((b) => visibleAddrs.has(b.addr)) : blocks;
    const graphEdges = visibleAddrs ? edges.filter((e) => visibleAddrs.has(e.from) && visibleAddrs.has(e.to)) : edges;
    const svgNodes = graphBlocks.map(b => ({
      addr: b.addr,
      label: window._annotations?.[b.addr]?.name || undefined,
      sublabel: `${(b.lines || []).length} instr.`,
      lines: b.lines,
      caseLabels: b.incoming_case_labels || [],
    }));
    const rerenderCfgGraph = () => {
      if (getStaticBinaryPath() === currentBinaryPath) {
        const fa = (typeof cfgUiState !== 'undefined' ? cfgUiState.funcAddr : '') || undefined;
        vscode.postMessage({
          type: 'hubLoadCfg',
          binaryPath: currentBinaryPath,
          funcAddr: fa,
          useCache: document.getElementById('useCache')?.checked !== false,
        });
      }
    };
    const svgEl = renderGraphSvg(svgNodes, graphEdges, {
      zoomState,
      padX: 56,
      padY: 52,
      lanePadX: 32,
      maxPerRow: 4,
      expandedAddrs: cfgState.expandedAddrs,
      onExpandedChange: (addrs) => { cfgState.expandedAddrs = addrs; },
      onNodeIsolate: (addr) => {
        cfgState.isolateAddr = addr;
        cfgState.isolateRadius = cfgState.isolateRadius ?? 1;
        rerenderCfgGraph();
      },
      onNodeClick: (addr) => vscode.postMessage({ type: 'hubGoToAddress', addr, binaryPath: getStaticBinaryPath() }),
    });
    // Build graph wrapper with DOM API
    const graphEl = document.createElement('div');
    graphEl.className = 'cfg-graph-view';
    const svgWrap = document.createElement('div');
    svgWrap.className = 'cfg-svg-wrap';
    const legendDiv = document.createElement('div');
    legendDiv.className = 'cfg-legend';
    const legendItems = [
      ['#88d8ff', 'solid', 'Fallthrough', 'Encha\u00eenement s\u00e9quentiel vers le bloc suivant'],
      ['#b48ead', 'solid', 'Jmp', 'Saut conditionnel ou inconditionnel (jmp, je, jne\u2026)'],
      ['#88c0d0', 'solid', 'Call', 'Appel de fonction (call)'],
      ['#d08770', 'dashed', 'Boucle', 'Back-edge : retour vers un bloc pr\u00e9c\u00e9dent (boucle)'],
    ];
    legendItems.forEach(([color, style, label, desc]) => {
      const item = document.createElement('span');
      item.className = 'cfg-legend-item';
      item.title = desc;
      const swatch = document.createElement('span');
      swatch.className = 'cfg-legend-swatch';
      swatch.style.background = color;
      if (style === 'dashed') swatch.style.background = `repeating-linear-gradient(90deg, ${color} 0 5px, transparent 5px 8px)`;
      item.appendChild(swatch);
      const txt = document.createTextNode(label);
      item.appendChild(txt);
      legendDiv.appendChild(item);
    });
    const isolateControls = document.createElement('span');
    isolateControls.className = 'cfg-isolate-controls';
    const isolateLabel = document.createElement('span');
    isolateLabel.className = 'cfg-legend-hint';
    isolateLabel.textContent = isolateFocus
      ? `Isolé: ${isolateFocus} (${graphBlocks.length}/${blocks.length})`
      : 'Alt+clic/clic droit: isoler';
    isolateControls.appendChild(isolateLabel);
    [1, 2].forEach((radius) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn btn-xs btn-secondary';
      btn.textContent = `±${radius}`;
      btn.disabled = !isolateFocus;
      if (isolateFocus && isolateRadius === radius) btn.classList.add('active');
      btn.addEventListener('click', () => {
        if (!isolateFocus) return;
        cfgState.isolateRadius = radius;
        rerenderCfgGraph();
      });
      isolateControls.appendChild(btn);
    });
    const allBtn = document.createElement('button');
    allBtn.type = 'button';
    allBtn.className = 'btn btn-xs btn-secondary';
    allBtn.textContent = 'Tout';
    allBtn.disabled = !isolateFocus;
    allBtn.addEventListener('click', () => {
      cfgState.isolateAddr = '';
      cfgState.isolateRadius = 1;
      rerenderCfgGraph();
    });
    isolateControls.appendChild(allBtn);
    legendDiv.appendChild(isolateControls);
    const hintSpan = document.createElement('span');
    hintSpan.className = 'cfg-legend-hint';
    hintSpan.textContent = 'Molette: zoom \u2014 Drag n\u0153ud \u2014 Shift+clic: chemin \u2014 Double-clic: plus/moins de code';
    legendDiv.appendChild(hintSpan);
    const zoomWrap = document.createElement('div');
    zoomWrap.className = 'cfg-svg-zoom';
    const innerWrap = document.createElement('div');
    innerWrap.className = 'cfg-svg-inner';
    innerWrap.appendChild(svgEl);
    zoomWrap.appendChild(innerWrap);
    svgWrap.appendChild(legendDiv);
    svgWrap.appendChild(zoomWrap);
    graphEl.appendChild(svgWrap);
    if (svgEl._tooltip) graphEl.appendChild(svgEl._tooltip);
    // Assemble and wire up
    tableEl.style.display = 'none';
    container.replaceChildren(tableEl, graphEl);
    let activeCfgBlockAddr = null;
    let zs = null;

    function findCfgBlockAddr(addr) {
      const normalized = normalizeHexAddress(addr);
      if (!normalized) return null;
      for (const block of blocks) {
        if (normalizeHexAddress(block.addr) === normalized) return block.addr;
        if ((block.lines || []).some((ln) => normalizeHexAddress(ln.addr) === normalized)) return block.addr;
      }
      return null;
    }

    function updateCfgSearchFilter() {
      const rawQuery = String(document.getElementById('cfgSearchInput')?.value || '');
      const q = rawQuery.toLowerCase();
      cfgState.search = rawQuery;
      svgEl.querySelectorAll('.cfg-node').forEach((g) => {
        const addr = (g.dataset.addr || '').toLowerCase();
        const text = (g.textContent || '').toLowerCase();
        const isActive = g.classList.contains('is-active');
        g.style.opacity = (!q || addr.includes(q) || text.includes(q) || isActive) ? '1' : '0.15';
      });
    }

    function setCfgActiveAddr(addr, opts = {}) {
      const blockAddr = findCfgBlockAddr(addr);
      container._cfgState = container._cfgState || {};
      container._cfgState.activeAddr = addr || '';
      cfgState.activeAddr = addr || '';
      if (activeCfgBlockAddr && rowEls[activeCfgBlockAddr]) rowEls[activeCfgBlockAddr].classList.remove('cfg-row-active');
      activeCfgBlockAddr = blockAddr;
      if (activeCfgBlockAddr && rowEls[activeCfgBlockAddr]) {
        rowEls[activeCfgBlockAddr].classList.add('cfg-row-active');
        if (opts.revealTable && tableEl.style.display !== 'none') {
          rowEls[activeCfgBlockAddr].scrollIntoView({ block: 'center', behavior: opts.instant ? 'auto' : 'smooth' });
        }
      }
      const nodeAddr = svgEl._setActiveAddress ? svgEl._setActiveAddress(addr) : null;
      updateCfgSearchFilter();
      if (nodeAddr && opts.reveal && graphEl.style.display !== 'none' && zs?.centerOnBox && svgEl._getNodeBox) {
        const box = svgEl._getNodeBox(nodeAddr);
        if (box) zs.centerOnBox(box, { minScale: 0.75, maxScale: 1.1 });
      }
      return blockAddr;
    }

    container._cfgState = {
      activeAddr: cfgState.activeAddr || window._lastDisasmAddr || '',
      setActiveAddr: setCfgActiveAddr,
    };

    const viewToggle = container.closest('.static-panel')?.querySelectorAll('input[name="cfgView"]');
    const showTable = () => {
      cfgState.viewMode = 'table';
      _saveStorage({ cfgViewMode: 'table' });
      tableEl.style.display = '';
      graphEl.style.display = 'none';
      if (container._cfgState?.activeAddr) setCfgActiveAddr(container._cfgState.activeAddr, { revealTable: true, instant: true });
    };
    const showGraph = () => {
      cfgState.viewMode = 'graph';
      _saveStorage({ cfgViewMode: 'graph' });
      tableEl.style.display = 'none';
      graphEl.style.display = '';
      const restoreView = cfgState.graphView && zs?.setViewState;
      if (restoreView) {
        requestAnimationFrame(() => {
          requestAnimationFrame(() => zs.setViewState(cfgState.graphView));
        });
      } else {
        requestGraphFit(graphEl);
      }
      if (container._cfgState?.activeAddr) {
        requestAnimationFrame(() => {
          requestAnimationFrame(() => setCfgActiveAddr(container._cfgState.activeAddr, { reveal: !restoreView, instant: true }));
        });
      }
    };
    viewToggle?.forEach((input) => {
      input.addEventListener('change', () => { (input.value === 'table' ? showTable : showGraph)(); });
    });
    zs = initCfgZoom(zoomWrap);
    if (zs) {
      Object.assign(zoomState, zs);
      zs.onChange = (view) => { cfgState.graphView = view; };
    }
    // Search filter
    const cfgSearchInput = document.getElementById('cfgSearchInput');
    if (cfgSearchInput) {
      cfgSearchInput.value = cfgState.search || '';
      cfgSearchInput.addEventListener('input', () => {
        _saveStorage({ cfgSearch: cfgSearchInput.value || '' });
        updateCfgSearchFilter();
      });
    }
    const preferredCfgView = container.closest('.static-panel')?.querySelector(`input[name="cfgView"][value="${cfgState.viewMode === 'table' ? 'table' : 'graph'}"]`);
    if (preferredCfgView) preferredCfgView.checked = true;
    if (cfgState.viewMode === 'table') showTable();
    else showGraph();
    updateCfgSearchFilter();
    // Fit button + auto-fit on first render
    const btnCfgFit = document.getElementById('btnCfgFit');
    if (btnCfgFit && zs) {
      btnCfgFit.addEventListener('click', () => zs.fitToView());
    }
    if (zs?.requestFit) zs.requestFit();
    const _pendingHighlight = window._pendingCfgHighlightAddr || container._cfgState?.activeAddr || '';
    if (_pendingHighlight) {
      window._pendingCfgHighlightAddr = null;
      // Apply class immediately (synchronous) so the border is set on first paint
      setCfgActiveAddr(_pendingHighlight, { reveal: false, instant: true });
      // Schedule centering after layout (needs measured coordinates)
      requestAnimationFrame(() => {
        requestAnimationFrame(() => setCfgActiveAddr(_pendingHighlight, { reveal: true, revealTable: tableEl.style.display !== 'none', instant: true }));
      });
    }
    reportStaticWebviewPerf('cfg.render', renderStarted, {
      blocks: blocks.length,
      edges: edges.length,
      graphBlocks: graphBlocks.length,
      graphEdges: graphEdges.length,
      functions: functions.length,
      viewMode: cfgState.viewMode || '',
      funcAddr: activeFuncAddr || '',
    });
    return;
  }
  if (msg.type === 'hubCallGraph') {
    if (isStaleStaticBinaryResponse(msg, 'static-callgraph')) return;
    const renderStarted = performance.now();
    const container = document.getElementById('callgraphContent');
    if (!container) return;
    const currentBinaryPath = getStaticBinaryPath() || '';
    const responseBinaryPath = String(msg.binaryPath || '').trim();
    tabDataCache.callgraph = { binaryPath: responseBinaryPath || currentBinaryPath };
    const cgState = getGraphUiState('callgraph', currentBinaryPath);
    const cg = msg.callGraph || { nodes: [], edges: [] };
    const cgEdges = cg.edges || [];
    const cgNodes = cg.nodes || [];
    vscode.postMessage({
      type: 'hubDebugLog',
      scope: 'static-callgraph',
      event: 'received',
      details: {
        currentBinaryPath,
        responseBinaryPath,
        nodes: cgNodes.length,
        edges: cgEdges.length,
      },
    });
    if (cgEdges.length === 0 && cgNodes.length === 0) {
      const bp = getStaticBinaryPath();
      const hint = bp ? 'Aucun appel détecté. Ouvrez le désassemblage puis rechargez.' : 'Ouvrez d\'abord le désassemblage.';
      const btnHtml = bp ? '' : `<button type="button" class="btn btn-primary" id="btnCgOpenDisasm">Ouvrir le désassemblage</button>`;
      container.innerHTML = `<p class="hint">${hint}</p>${btnHtml}`;
      document.getElementById('btnCgOpenDisasm')?.addEventListener('click', () => {
        if (bp) vscode.postMessage({ type: 'hubOpenDisasm', binaryPath: bp, useCache: true });
        else vscode.postMessage({ type: 'requestBinarySelection' });
      });
      reportStaticWebviewPerf('callgraph.render', renderStarted, {
        nodes: cgNodes.length,
        edges: cgEdges.length,
        empty: true,
      });
      return;
    }
    // Build unique node list from edges, with is_external info
    const nodeMap = {};
    const extSet = new Set();
    cgNodes.forEach(n => {
      const annName = window._annotations?.[n.addr]?.name;
      nodeMap[n.addr] = annName || n.name || n.addr;
      if (n.is_external) extSet.add(n.addr);
    });
    cgEdges.forEach(e => {
      if (!nodeMap[e.from]) nodeMap[e.from] = e.from_name || e.from;
      if (!nodeMap[e.to]) nodeMap[e.to] = e.to_name || e.to;
    });

    // --- Table view ---
    const radj = window.cfgHelpers.buildReverseAdj(cgEdges.map(e => ({ from: e.from, to: e.to })));
    const cgTableEl = document.createElement('div');
    cgTableEl.className = 'cfg-table-view';
    const cgTable = document.createElement('table');
    cgTable.className = 'data-table';
    const cgThead = cgTable.createTHead();
    const cgHrow = cgThead.insertRow();
    ['Fonction', 'Adresse', 'Type', 'Appelants'].forEach(h => {
      const th = document.createElement('th');
      th.textContent = h;
      cgHrow.appendChild(th);
    });
    const cgTbody = cgTable.createTBody();
    const cgRowEls = {};
    Object.entries(nodeMap).sort((a, b) => a[1].localeCompare(b[1])).forEach(([addr, name]) => {
      const isExt = extSet.has(addr);
      const callers = (radj[addr] || []).map(a => nodeMap[a] || a).join(', ') || '\u2014';
      const row = cgTbody.insertRow();
      row.dataset.addr = addr;
      cgRowEls[addr] = row;
      const td1 = row.insertCell();
      const nameCode = document.createElement('code');
      nameCode.className = 'addr-link';
      nameCode.dataset.addr = addr;
      nameCode.textContent = name;
      nameCode.style.cursor = 'pointer';
      nameCode.style.color = isExt ? '#88c0d0' : '#88d8ff';
      nameCode.addEventListener('click', (ev) => {
        ev.stopPropagation();
        syncCallGraphActiveAddress(addr, { reveal: isStaticTabActive('callgraph') });
        vscode.postMessage({ type: 'hubGoToAddress', addr, binaryPath: getStaticBinaryPath() });
      });
      td1.appendChild(nameCode);
      const td2 = row.insertCell();
      td2.textContent = addr;
      td2.style.fontFamily = 'monospace';
      td2.style.fontSize = '11px';
      const td3 = row.insertCell();
      td3.textContent = isExt ? 'Externe' : 'Interne';
      td3.style.color = isExt ? '#88c0d0' : '#88d8ff';
      const td4 = row.insertCell();
      td4.textContent = callers;
      td4.style.fontSize = '11px';
    });
    const cgHintP = document.createElement('p');
    cgHintP.className = 'hint';
    cgHintP.textContent = `${Object.keys(nodeMap).length} fonction(s) \u2014 ${cgEdges.length} appel(s).`;
    cgTableEl.appendChild(cgTable);
    cgTableEl.appendChild(cgHintP);

    // --- Graph view ---
    const svgNodes = Object.entries(nodeMap).map(([addr, name]) => ({
      addr, label: name, isExternal: extSet.has(addr),
    }));
    const svgEdges = cgEdges.map(e => ({ from: e.from, to: e.to, type: 'call' }));
    const zoomState = { scale: 1 };
    const svgEl = renderGraphSvg(svgNodes, svgEdges, {
      nodeH: 76,
      padX: 104,
      padY: 96,
      maxPerRow: 4,
      zoomState,
      onNodeClick: (addr) => vscode.postMessage({ type: 'hubGoToAddress', addr, binaryPath: getStaticBinaryPath() }),
    });
    const graphEl = document.createElement('div');
    graphEl.className = 'cfg-graph-view';
    const svgWrap = document.createElement('div');
    svgWrap.className = 'cfg-svg-wrap';
    const zoomWrap = document.createElement('div');
    zoomWrap.className = 'cfg-svg-zoom';
    const innerWrap = document.createElement('div');
    innerWrap.className = 'cfg-svg-inner';
    innerWrap.appendChild(svgEl);
    zoomWrap.appendChild(innerWrap);
    // Call Graph legend
    const cgLegendDiv = document.createElement('div');
    cgLegendDiv.className = 'cfg-legend';
    const cgLegendItems = [
      ['#88c0d0', 'solid', 'Appel', 'Appel de fonction d\u00e9tect\u00e9 dans le code'],
      ['#d08770', 'dashed', 'Boucle', 'Appel r\u00e9cursif ou cyclique'],
      ['#88c0d0', 'ext', 'Externe', 'Fonction import\u00e9e (PLT/libc) \u2014 bordure pointill\u00e9e'],
      ['#88d8ff', 'int', 'Interne', 'Fonction d\u00e9finie dans le binaire'],
    ];
    cgLegendItems.forEach(([color, style, label, desc]) => {
      const item = document.createElement('span');
      item.className = 'cfg-legend-item';
      item.title = desc;
      const swatch = document.createElement('span');
      swatch.className = 'cfg-legend-swatch';
      if (style === 'ext') {
        swatch.style.background = `repeating-linear-gradient(90deg, ${color} 0 4px, transparent 4px 6px)`;
      } else if (style === 'dashed') {
        swatch.style.background = `repeating-linear-gradient(90deg, ${color} 0 5px, transparent 5px 8px)`;
      } else {
        swatch.style.background = color;
      }
      item.appendChild(swatch);
      item.appendChild(document.createTextNode(label));
      cgLegendDiv.appendChild(item);
    });
    const cgHintSpan = document.createElement('span');
    cgHintSpan.className = 'cfg-legend-hint';
    cgHintSpan.textContent = 'Molette: zoom \u2014 Drag n\u0153ud \u2014 Shift+clic: chemin';
    cgLegendDiv.appendChild(cgHintSpan);

    svgWrap.appendChild(cgLegendDiv);
    svgWrap.appendChild(zoomWrap);
    graphEl.appendChild(svgWrap);
    if (svgEl._tooltip) graphEl.appendChild(svgEl._tooltip);

    // Assemble and wire up toggle
    cgTableEl.style.display = 'none';
    container.replaceChildren(cgTableEl, graphEl);
    const callGraphAddrs = Object.keys(nodeMap);
    const callGraphAddrMap = Object.fromEntries(callGraphAddrs.map((addr) => [normalizeHexAddress(addr), addr]));
    let activeCallGraphAddr = null;
    let zs = null;

    function resolveCallGraphAddr(addr) {
      const nearest = findNearestFunctionStart(addr, callGraphAddrs);
      return callGraphAddrMap[normalizeHexAddress(nearest)] || null;
    }

    function updateCallGraphSearchFilter() {
      const rawQuery = String(document.getElementById('cgSearchInput')?.value || '');
      const q = rawQuery.toLowerCase();
      cgState.search = rawQuery;
      svgEl.querySelectorAll('.cfg-node').forEach((g) => {
        const addr = (g.dataset.addr || '').toLowerCase();
        const text = (g.textContent || '').toLowerCase();
        const isActive = g.classList.contains('is-active');
        g.style.opacity = (!q || addr.includes(q) || text.includes(q) || isActive) ? '1' : '0.15';
      });
    }

    function setCallGraphActiveAddr(addr, opts = {}) {
      const nodeAddr = resolveCallGraphAddr(addr);
      container._cgState = container._cgState || {};
      container._cgState.activeAddr = addr || '';
      cgState.activeAddr = addr || '';
      if (activeCallGraphAddr && cgRowEls[activeCallGraphAddr]) cgRowEls[activeCallGraphAddr].classList.remove('cfg-row-active');
      activeCallGraphAddr = nodeAddr;
      if (activeCallGraphAddr && cgRowEls[activeCallGraphAddr]) {
        cgRowEls[activeCallGraphAddr].classList.add('cfg-row-active');
        if (opts.revealTable && cgTableEl.style.display !== 'none') {
          cgRowEls[activeCallGraphAddr].scrollIntoView({ block: 'center', behavior: opts.instant ? 'auto' : 'smooth' });
        }
      }
      const selectedNodeAddr = nodeAddr && svgEl._setActiveNode ? svgEl._setActiveNode(nodeAddr) : null;
      updateCallGraphSearchFilter();
      if (selectedNodeAddr && opts.reveal && graphEl.style.display !== 'none' && zs?.centerOnBox && svgEl._getNodeBox) {
        const box = svgEl._getNodeBox(selectedNodeAddr);
        if (box) zs.centerOnBox(box, { minScale: 0.75, maxScale: 1.1 });
      }
      return selectedNodeAddr;
    }

    container._cgState = {
      activeAddr: cgState.activeAddr || window._lastDisasmAddr || '',
      setActiveAddr: setCallGraphActiveAddr,
    };

    const cgViewToggle = container.closest('.static-panel')?.querySelectorAll('input[name="cgView"]');
    const showCgTable = () => {
      cgState.viewMode = 'table';
      _saveStorage({ cgViewMode: 'table' });
      cgTableEl.style.display = '';
      graphEl.style.display = 'none';
      if (container._cgState?.activeAddr) setCallGraphActiveAddr(container._cgState.activeAddr, { revealTable: true, instant: true });
    };
    const showCgGraph = () => {
      cgState.viewMode = 'graph';
      _saveStorage({ cgViewMode: 'graph' });
      cgTableEl.style.display = 'none';
      graphEl.style.display = '';
      const restoreView = cgState.graphView && zs?.setViewState;
      if (restoreView) {
        requestAnimationFrame(() => {
          requestAnimationFrame(() => zs.setViewState(cgState.graphView));
        });
      } else {
        requestGraphFit(graphEl);
      }
      if (container._cgState?.activeAddr) {
        requestAnimationFrame(() => {
          requestAnimationFrame(() => setCallGraphActiveAddr(container._cgState.activeAddr, { reveal: !restoreView, instant: true }));
        });
      }
    };
    cgViewToggle?.forEach(input => {
      input.addEventListener('change', () => { (input.value === 'table' ? showCgTable : showCgGraph)(); });
    });
    zs = initCfgZoom(zoomWrap);
    if (zs) {
      Object.assign(zoomState, zs);
      zs.onChange = (view) => { cgState.graphView = view; };
    }
    // Search filter
    const cgSearchInput = document.getElementById('cgSearchInput');
    if (cgSearchInput) {
      cgSearchInput.value = cgState.search || '';
      cgSearchInput.addEventListener('input', () => {
        _saveStorage({ cgSearch: cgSearchInput.value || '' });
        updateCallGraphSearchFilter();
      });
    }
    const preferredCgView = container.closest('.static-panel')?.querySelector(`input[name="cgView"][value="${cgState.viewMode === 'table' ? 'table' : 'graph'}"]`);
    if (preferredCgView) preferredCgView.checked = true;
    if (cgState.viewMode === 'graph') showCgGraph();
    else showCgTable();
    updateCallGraphSearchFilter();
    // Fit button + auto-fit on first render
    const btnCgFit = document.getElementById('btnCgFit');
    if (btnCgFit && zs) {
      btnCgFit.addEventListener('click', () => zs.fitToView());
    }
    if (zs?.requestFit && !cgState.graphView && cgState.viewMode === 'graph') zs.requestFit();
    if (container._cgState?.activeAddr) {
      requestAnimationFrame(() => {
        requestAnimationFrame(() => setCallGraphActiveAddr(container._cgState.activeAddr, { reveal: isStaticTabActive('callgraph'), instant: true }));
      });
    }
    reportStaticWebviewPerf('callgraph.render', renderStarted, {
      nodes: cgNodes.length,
      edges: cgEdges.length,
      renderedNodes: Object.keys(nodeMap).length,
      viewMode: cgState.viewMode || '',
    });
    return;
  }
  if (msg.type === 'hubDiscoveredFunctions') {
    if (isStaleStaticBinaryResponse(msg, 'static-functions-discovered')) return;
    tabDataCache.discovered = { binaryPath: getStaticBinaryPath() };
    const container = document.getElementById('functionsContent');
    const countEl = document.getElementById('functionsCount');
    if (!container) return;
    const list = msg.functions || [];
    const rows = buildFunctionsRowsFromDiscovered(list);
    const radar = buildFallbackFunctionsRadarFromRows(rows, { rawMode: true });
    window.discoveredFunctionsCache = rows;
    populateDecompileSelect(window.symbolsCache || []);
    renderAnnotationsList();
    if (list.length === 0) {
      const bp = getStaticBinaryPath();
      let hint = msg.analyzed ? 'Aucune fonction supplémentaire trouvée (tous les prologues correspondent à des symboles connus).' : 'Ouvrez d\'abord le désassemblage.';
      if (msg.error) hint = `Erreur : ${msg.error}`;
      const btnHtml = msg.analyzed ? '' : `<br/><button type="button" class="btn btn-primary" id="btnDiscOpenDisasm">Ouvrir le désassemblage</button>`;
      renderFunctionsRadar(radar);
      renderFunctionDetails(null);
      if (countEl) countEl.textContent = '0 fonction';
      container.innerHTML = `<p class="hint">${escapeHtml(hint)}</p>${btnHtml}`;
      document.getElementById('btnDiscOpenDisasm')?.addEventListener('click', () => {
        if (bp) vscode.postMessage({ type: 'hubOpenDisasm', binaryPath: bp, useCache: false });
      });
    } else {
      renderFunctionsWorkspace(rows, radar, { rawMode: true });
    }
    return;
  }
  if (msg.type === 'hubFunctionsDone') {
    if (isStaleStaticBinaryResponse(msg, 'static-functions')) return;
    tabDataCache.discovered = { binaryPath: getStaticBinaryPath() };
    const container = document.getElementById('functionsContent');
    const countEl = document.getElementById('functionsCount');
    if (!container) return;

    const { symbols, cc, radar, error } = msg.data || {};
    if (error) {
      if (countEl) countEl.textContent = 'Erreur';
      renderFunctionsRadar({ error });
      renderFunctionDetails(null);
      container.innerHTML = '<p class="hint">Erreur : ' + escapeHtml(error) + '</p>';
      return;
    }

    const symList = (symbols && symbols.symbols) ? symbols.symbols : [];
    const conventions = (cc && cc.conventions) ? cc.conventions : {};
    const radarFunctions = Array.isArray(radar?.functions) ? radar.functions : [];
    const rows = buildFunctionsRowsFromRadarAndSymbols(symList, conventions, radarFunctions);
    populateDecompileSelect(window.symbolsCache || symList);
    renderFunctionsWorkspace(rows, radar || buildFallbackFunctionsRadarFromRows(rows));
    renderAnnotationsList();
    if (typeof tabDataCache !== 'undefined') {
      tabDataCache['discovered'] = { binaryPath: getStaticBinaryPath() };
    }
    return;
  }
  if (msg.type === 'hubDecompilerList') {
    const newResult = msg.result || {};
    if (window._decompilerImageUpdates) {
      const dockerImages = newResult._meta?.docker_images || {};
      Object.keys(window._decompilerImageUpdates).forEach((id) => {
        if (!dockerImages[id] || window._decompilerImageUpdates[id]?.image !== dockerImages[id]) {
          delete window._decompilerImageUpdates[id];
        }
      });
    }
    _detectDecompilerStateChanges(newResult);
    populateDecompilerProfiles(newResult);
    _renderDecompilerStatusList(newResult);
    return;
  }
  if (msg.type === 'hubDecompilerImageUpdates') {
    window._decompilerImageUpdates = {
      ...(window._decompilerImageUpdates || {}),
      ...(msg.updates || {}),
    };
    _renderDecompilerStatusList({ ..._decompilerAvailability, _meta: _decompilerMeta });
    return;
  }
  if (msg.type === 'hubDockerRuntimeStatus') {
    window._dockerRuntimeStatus = msg.status || null;
    _renderDecompilerStatusList({ ..._decompilerAvailability, _meta: _decompilerMeta });
    return;
  }
  if (msg.type === 'hubDecompilerPullProgress') {
    const area = document.getElementById('decompilerPullArea_' + msg.decompiler);
    if (!area) return;
    const log = area.querySelector('.decompiler-pull-log');
    const bar = area.querySelector('.decompiler-pull-progress');
    if (log && msg.line) {
      const entry = document.createElement('div');
      entry.textContent = msg.line;
      log.appendChild(entry);
      log.scrollTop = log.scrollHeight;
    }
    if (bar && msg.percent != null) bar.value = msg.percent;
    return;
  }
  if (msg.type === 'hubDecompilerPullDone') {
    const area = document.getElementById('decompilerPullArea_' + msg.decompiler);
    if (area) {
      const bar = area.querySelector('.decompiler-pull-progress');
      if (bar) bar.value = msg.ok ? 100 : 0;
      const status = document.createElement('div');
      status.className = msg.ok ? 'decompiler-pull-status--ok' : 'decompiler-pull-status--err';
      const doneLabel = msg.mode === 'update'
        ? 'Image mise à jour.'
        : msg.mode === 'force'
          ? 'Repull terminé.'
          : 'Image t\u00E9l\u00E9charg\u00E9e.';
      status.textContent = msg.ok ? doneLabel : ('Échec : ' + (msg.error || 'erreur inconnue'));
      area.appendChild(status);
    }
    return;
  }
  if (msg.type === 'hubCommandResult') {
    _onDecompilerCommandResult(msg);
    return;
  }
  if (msg.type === 'hubDecompileStatus') {
    const { decompiler, status, score, errorReason } = msg;
    decompileUiState.pillStatuses[decompiler] = { status, score, errorReason };
    _refreshDecompilePills();
    return;
  }
  if (msg.type === 'hubDecompile') {
    const renderStarted = performance.now();
    const container = document.getElementById('decompileContent');
    if (!container) return;
    const responseQuality = _normalizeDecompileQuality(msg.quality || msg.result?.quality || decompileUiState.quality || 'normal');
    const payload = {
      result: msg.result || {},
      addr: msg.addr || '',
      full: !!msg.full,
      decompiler: typeof msg.decompiler === 'string' ? msg.decompiler : _getRequestedDecompilerForQuality(responseQuality),
      quality: responseQuality,
      provider: String(msg.provider || _getConfiguredDecompilerProvider() || 'auto'),
      binaryPath: msg.binaryPath || getStaticBinaryPath() || decompileUiState.renderedBinaryPath || '',
      funcName: String(msg.funcName || getDecompileSelectionContext().funcName || '').trim(),
      score: msg.score,
    };
    // Cache per-decompiler payload for pill switching
    if (payload.decompiler) {
      decompileUiState.payloads[payload.decompiler] = payload;
    }
    // Clean up pending requests — delete both the per-decompiler key and the auto key (decompiler='')
    const requestKey = buildDecompileRequestKey(payload.binaryPath, payload.decompiler, payload.quality, payload.addr, payload.full, payload.provider, payload.funcName);
    pendingDecompileRequests.delete(requestKey);
    const autoKey = buildDecompileRequestKey(payload.binaryPath, '', payload.quality, payload.addr, payload.full, payload.provider, payload.funcName);
    pendingDecompileRequests.delete(autoKey);
    cacheDecompileResult(requestKey, payload);
    // Track best decompiler when this result is better
    const forced = decompileUiState.forcedDecompiler;
    if (msg.isBetter) {
      decompileUiState.bestDecompiler = payload.decompiler;
    }
    // Stale-response guard: the user may have navigated to a different binary
    // or function while this (possibly slow, Docker-backed) decompile was in
    // flight. Bookkeeping above still applies (so the result is cached for
    // later), but the DOM must never be overwritten with a result for a
    // selection the user isn't looking at anymore — that's what produced the
    // intermittent "wrong pseudo-C / stuck loader" behavior.
    const currentSelection = getDecompileSelectionContext();
    const currentFull = !currentSelection.addr;
    const isStaleForCurrentSelection = payload.binaryPath !== (getStaticBinaryPath() || '')
      || payload.full !== currentFull
      || (!currentFull && payload.addr !== currentSelection.addr);
    if (isStaleForCurrentSelection) {
      _refreshDecompilePills();
      reportStaticWebviewPerf('decompile.render', renderStarted, {
        rendered: false,
        stale: true,
        decompiler: payload.decompiler,
        quality: payload.quality,
        full: payload.full,
      });
      return;
    }
    // Decide whether to render: auto mode renders first result + better results; forced mode renders matching decompiler only
    const shouldRender = (forced === '' && (msg.isBetter || !msg.isSilentUpdate))
      || (forced !== '' && forced === payload.decompiler);
    if (!shouldRender) {
      _refreshDecompilePills();
      reportStaticWebviewPerf('decompile.render', renderStarted, {
        rendered: false,
        silent: Boolean(msg.isSilentUpdate),
        decompiler: payload.decompiler,
        quality: payload.quality,
        full: payload.full,
      });
      return;
    }
    if (msg.isSilentUpdate && forced === '') {
      // Better result arrived silently in auto mode — flash update
      renderDecompilePayload(container, payload);
      container.classList.remove('decompile-content--flash');
      void container.offsetWidth; // reflow
      container.classList.add('decompile-content--flash');
      _refreshDecompilePills();
      reportStaticWebviewPerf('decompile.render', renderStarted, {
        rendered: true,
        silent: true,
        decompiler: payload.decompiler,
        quality: payload.quality,
        full: payload.full,
        textLength: String(payload.result?.code || payload.result?.text || '').length,
      });
      return;
    }
    renderDecompilePayload(container, payload);
    _refreshDecompilePills();
    reportStaticWebviewPerf('decompile.render', renderStarted, {
      rendered: true,
      silent: Boolean(msg.isSilentUpdate),
      decompiler: payload.decompiler,
      quality: payload.quality,
      full: payload.full,
      textLength: String(payload.result?.code || payload.result?.text || '').length,
    });
    return;
  }
  if (msg.type === 'hubRecherche' || msg.type === 'hubSearchBinaryResult') {
    if (isStaleStaticBinaryResponse(msg, 'static-search')) return;
    const renderStarted = performance.now();
    const results = msg.results || [];
    const err = msg.error;
    const tbody = document.getElementById('searchResultsBody');
    const bar = document.getElementById('searchResultsBar');
    const container = document.getElementById('searchResultsContainer');
    const countEl = document.getElementById('searchResultsCount');
    const binaryPath = getStaticBinaryPath();
    const binaryMeta = getCurrentBinaryMeta();
    const isRaw = binaryMeta?.kind === 'raw';
    const goToSearchOffset = (row) => {
      if (!binaryPath) return;
      const spanLength = getSearchResultSpanLength(row);
      if (isRaw && row?.vaddr_hex) {
        vscode.postMessage({ type: 'hubGoToAddress', addr: row.vaddr_hex, binaryPath, binaryMeta, spanLength });
        return;
      }
      const offsetValue = row?.offset_hex || row?.offset;
      if (offsetValue != null) {
        vscode.postMessage({ type: 'hubGoToFileOffset', fileOffset: String(offsetValue), binaryPath, binaryMeta, spanLength });
      }
    };
    const goToSearchAddress = (row) => {
      if (!binaryPath || !row?.vaddr_hex) return;
      vscode.postMessage({
        type: 'hubGoToAddress',
        addr: row.vaddr_hex,
        binaryPath,
        binaryMeta,
        spanLength: getSearchResultSpanLength(row),
      });
    };

    // Fallback: if new DOM elements are absent, use legacy rendering
    if (!tbody || !bar || !container || !countEl) {
      const legacyContainer = document.getElementById('searchBinaryContent');
      if (!legacyContainer) return;
      if (err) {
        legacyContainer.innerHTML = `<div class="search-results-empty"><p class="search-results-empty-title">Erreur</p><p class="search-results-empty-desc">${escapeHtml(err)}</p></div>`;
        reportStaticWebviewPerf('search.render', renderStarted, { error: true, results: results.length, legacy: true });
        return;
      }
      if (results.length === 0) {
        legacyContainer.innerHTML = `<div class="search-results-empty"><p class="search-results-empty-title">Aucune correspondance</p></div>`;
        reportStaticWebviewPerf('search.render', renderStarted, { results: 0, empty: true, legacy: true });
        return;
      }
      const rows = results.map(r => {
        const val = escapeHtml(String(r.value || '').substring(0, 48));
        const ctx = escapeHtml(String(r.context || '').substring(0, 80));
        const span = getSearchResultSpanLength(r);
        const vaddr = r.vaddr_hex ? `<code class="addr-link" data-vaddr="${escapeHtml(r.vaddr_hex)}" data-span="${escapeHtml(String(span))}">${escapeHtml(r.vaddr_hex)}</code>` : '—';
        return `<tr><td><code class="addr-link" data-offset="${escapeHtml(r.offset_hex)}" data-span="${escapeHtml(String(span))}">${escapeHtml(r.offset_hex)}</code></td><td>${vaddr}</td><td><code>${val}</code></td><td><code>${ctx}</code></td></tr>`;
      }).join('');
      legacyContainer.innerHTML = `<div class="search-results-header"><span>${results.length} correspondance(s)</span></div><table class="data-table"><thead><tr><th>Offset</th><th>Adresse</th><th>Valeur</th><th>Contexte</th></tr></thead><tbody>${rows}</tbody></table>`;
      legacyContainer.querySelectorAll('.addr-link').forEach(el => {
        el.style.cursor = 'pointer';
        el.addEventListener('click', () => {
          const span = normalizeSpanLength(el.dataset.span || 1);
          const row = {
            offset_hex: el.dataset.offset || '',
            vaddr_hex: el.dataset.vaddr || '',
            length: span,
          };
          if (el.dataset.vaddr) goToSearchAddress(row);
          else goToSearchOffset(row);
        });
      });
      reportStaticWebviewPerf('search.render', renderStarted, {
        results: results.length,
        rowsRendered: results.length,
        legacy: true,
      });
      return;
    }

    // ── New DOM rendering (E) ─────────────────────────────────────────────────
    if (err) {
      tbody.innerHTML = '';
      countEl.textContent = 'Erreur : ' + err;
      bar.hidden = false;
      container.hidden = true;
      reportStaticWebviewPerf('search.render', renderStarted, { error: true, results: results.length });
      return;
    }

    tbody.innerHTML = '';
    const display = results.slice(0, 500);
    display.forEach(r => {
      const tr = document.createElement('tr');
      const offsetTd = document.createElement('td');
      const offsetCode = document.createElement('code');
      offsetCode.textContent = String(r.offset_hex || '');
      if (r.offset_hex || r.offset != null) {
        offsetCode.className = 'addr-link';
        offsetCode.style.cursor = 'pointer';
        offsetCode.addEventListener('click', () => goToSearchOffset(r));
      }
      offsetTd.appendChild(offsetCode);

      const vaddrTd = document.createElement('td');
      if (r.vaddr_hex) {
        const vaddrCode = document.createElement('code');
        vaddrCode.textContent = String(r.vaddr_hex);
        vaddrCode.className = 'addr-link';
        vaddrCode.style.cursor = 'pointer';
        vaddrCode.addEventListener('click', () => goToSearchAddress(r));
        vaddrTd.appendChild(vaddrCode);
      } else {
        vaddrTd.textContent = '—';
      }

      const valueTd = document.createElement('td');
      valueTd.className = 'mono';
      valueTd.textContent = String(r.value || '').slice(0, 40);

      const lenTd = document.createElement('td');
      lenTd.textContent = String(r.length ?? '');

      const contextTd = document.createElement('td');
      contextTd.className = 'mono';
      contextTd.textContent = String(r.context || '').slice(0, 32);

      tr.append(offsetTd, vaddrTd, valueTd, lenTd, contextTd);
      tbody.appendChild(tr);
    });

    countEl.textContent = results.length > 500
      ? `${results.length} résultats (500 affichés)`
      : `${results.length} résultat${results.length !== 1 ? 's' : ''}`;
    bar.hidden = false;
    container.hidden = false;

    window._searchResults = results;
    reportStaticWebviewPerf('search.render', renderStarted, {
      results: results.length,
      rowsRendered: display.length,
      truncated: results.length > display.length,
    });
    return;
  }
  if (msg.type === 'hubActiveAddr') {
    const spanLength = normalizeSpanLength(msg.spanLength || 1);
    setActiveAddressContext(msg.addr, spanLength);
    const ann = window._annotations?.[msg.addr];
    focusAnnotationEditor(msg.addr, ann, { focus: false });
    const cfgBlockFound = syncCfgActiveAddress(msg.addr, {
      reveal: isStaticTabActive('cfg'),
      revealTable: isStaticTabActive('cfg') && document.querySelector('#cfgContent .cfg-table-view')?.style.display !== 'none',
    });
    // Auto-switch CFG function scope: demander au backend de trouver la bonne fonction via BFS inverse
    if (!cfgBlockFound) {
      const cfgPane = document.getElementById('cfgContent');
      if (cfgPane && cfgPane.style.display !== 'none') {
        const bp = getStaticBinaryPath();
        if (bp) {
          cfgUiState.activeAddr = msg.addr;
          window._pendingCfgHighlightAddr = msg.addr;
          tabDataCache.cfg = null;
          postBinaryAwareMessage('hubLoadCfgForAddr', { binaryPath: bp, addr: msg.addr });
        }
      }
    }
    syncCallGraphActiveAddress(msg.addr, {
      reveal: isStaticTabActive('callgraph'),
      revealTable: isStaticTabActive('callgraph') && document.querySelector('#callgraphContent .cfg-table-view')?.style.display !== 'none',
    });
    const decompileAddr = syncDecompileSelection(msg.addr, {
      forceContext: isStaticTabActive('decompile') && decompileUiState.selectionMode !== 'manual',
    });
    if (isStaticTabActive('decompile')) {
      const currentBinaryPath = getStaticBinaryPath() || '';
      const currentQuality = _normalizeDecompileQuality(document.getElementById('decompileQualitySelect')?.value || decompileUiState.quality || 'normal');
      const currentDecompiler = _getRequestedDecompilerForQuality(currentQuality);
      const currentProvider = _getConfiguredDecompilerProvider();
      const renderedAddr = decompileUiState.renderedAddr || '';
      const shouldRefreshDecompile = currentBinaryPath
        && (
          decompileUiState.renderedBinaryPath !== currentBinaryPath
          || decompileUiState.renderedDecompiler !== currentDecompiler
          || decompileUiState.renderedProvider !== currentProvider
          || decompileUiState.renderedQuality !== currentQuality
          || renderedAddr !== (decompileAddr || '')
        );
      if (shouldRefreshDecompile) requestDecompileForCurrentSelection();
    }
    if (hexSections.length) {
      setHexActiveAddress(msg.addr, {
        spanLength,
        reveal: isStaticTabActive('hex'),
        instant: !isStaticTabActive('hex'),
      });
    }
    if (isStaticTabActive('stack')) {
      syncStackFrameForContext(msg.addr);
    }
    updateDisasmSessionSummary();
    return;
  }
  if (msg.type === 'hubAnnotationSaved') {
    // Filet de sécurité : hubAnnotations (envoyé juste avant) fait déjà le
    // refresh gardé par signature ; ne rebuild ici que si l'overlay du .asm
    // (name/comment) a réellement changé — jamais pour bookmarks/reviews.
    const bp = msg.binaryPath;
    if (bp && refreshDisasmForAnnotations(bp, window._annotations)) {
      clearDecompileCaches();
      tabDataCache.cfg = null;
      tabDataCache.callgraph = null;
    }
    return;
  }
  if (msg.type === 'hubAnnotations') {
    if (isStaleStaticBinaryResponse(msg, 'static-annotations')) return;
    // Annotations loaded — could highlight addresses
    window._annotations = msg.annotations || {};
    refreshDisasmForAnnotations(msg.binaryPath, window._annotations);
    clearDecompileCaches();
    if (typeof populateDecompileSelect === 'function') {
      populateDecompileSelect(window.symbolsCache || []);
    }
    renderBookmarks();
    renderCurrentFunctionsWorkspace();
    syncFunctionsSelectionFromContext(window._lastDisasmAddr || functionsUiState.selectedAddr);
    updateActiveContextBars(window._lastDisasmAddr);
    return;
  }
  if (msg.type === 'hubSyncHexToAddr') {
    const spanLength = normalizeSpanLength(msg.spanLength || 1);
    setActiveAddressContext(msg.addr, spanLength);
    if (hexSections.length) scrollHexToVaddr({ addr: msg.addr, spanLength });
    return;
  }
  if (msg.type === 'hubHexView') {
    if (isStaleStaticBinaryResponse(msg, 'static-hex')) return;
    const renderStarted = performance.now();
    tabDataCache.hex = { binaryPath: getStaticBinaryPath() };
    const result = msg.result || {};
    const container = document.getElementById('hexContent');
    if (!container) return;
    if (result.error && !(result.rows?.length)) {
      resetHexDomState();
      window._lastHexRows = [];
      hexSections = result.sections || [];
      hexRenderInProgress = false;
      updateHexRenderStatus(0, 0, false);
      container.replaceChildren();
      const p = document.createElement('p');
      p.className = 'hint';
      p.textContent = result.error;
      container.appendChild(p);
      reportStaticWebviewPerf('hex.render', renderStarted, {
        error: true,
        rows: 0,
        sections: hexSections.length,
      });
      return;
    }
    hexSections = result.sections || [];
    renderHexTable(container, result.rows || [], hexSections);
    renderHexSectionLegend(hexSections, {
      arch: result.arch || '',
      bits: result.bits || 0,
      endianness: result.endianness || '',
      ptrSize: result.ptr_size || 0,
    });
    if (hexPendingScrollVaddr) {
      const pending = hexPendingScrollVaddr;
      hexPendingScrollVaddr = null;
      requestAnimationFrame(() => scrollHexToVaddr(pending));
    }
    const offInput = document.getElementById('hexOffsetInput');
    if (offInput) offInput.value = '0x' + hexCurrentOffset.toString(16);
    const prevBtn = document.getElementById('btnHexPrev');
    const nextBtn = document.getElementById('btnHexNext');
    if (prevBtn) prevBtn.disabled = hexCurrentOffset === 0;
    if (nextBtn) nextBtn.disabled = (result.rows?.length || 0) < Math.ceil(hexCurrentLength / 16);
    reportStaticWebviewPerf('hex.render', renderStarted, {
      rows: Array.isArray(result.rows) ? result.rows.length : 0,
      sections: hexSections.length,
      error: Boolean(result.error),
      offset: hexCurrentOffset,
    });
    return;
  }
  if (msg.type === 'hubPatchResult') {
    if (isStaleStaticBinaryResponse(msg, 'static-patch')) return;
    const result = msg.result || {};
    const status = document.getElementById('hexPatchStatus');
    if (status) {
      status.className = 'hex-patch-status ' + (result.ok ? 'ok' : 'error');
      status.textContent = result.ok
        ? `Patched ${result.written} byte(s) at 0x${result.offset?.toString(16)}`
        : `Error: ${result.error}`;
    }
    if (result.ok) {
      tabDataCache.hex = null;
      loadHexView(getStaticBinaryPath(), hexCurrentOffset, hexCurrentLength);
    }
    return;
  }
  if (msg.type === 'hubPatchesDone') {
    if (isStaleStaticBinaryResponse(msg, 'static-patches')) return;
    const patchList = document.getElementById('patchList');
    const revertAllBtn = document.getElementById('btnRevertAll');
    const patchSection = document.getElementById('patchManagerSection');
    if (!patchList) return;

    const patches = (msg.data && msg.data.patches) ? msg.data.patches : [];
    const redoPatches = (msg.data && msg.data.redo_patches) ? msg.data.redo_patches : [];
    hexPatchHistory = Array.isArray(patches) ? patches.slice() : [];
    hexPatchRedoHistory = Array.isArray(redoPatches) ? redoPatches.slice() : [];
    updateHexPatchButtons();

    if (patches.length === 0 && redoPatches.length === 0) {
      if (patchSection) patchSection.hidden = true;
      patchList.innerHTML = '<p class="hint" style="margin:6px 10px;">Aucun patch appliqué.</p>';
      if (revertAllBtn) revertAllBtn.style.display = 'none';
      return;
    }

    if (patchSection) patchSection.hidden = false;
    if (revertAllBtn) revertAllBtn.style.display = patches.length > 0 ? '' : 'none';

    const thead = '<thead><tr>' +
      '<th style="font-size:11px;padding:3px 6px;">Offset</th>' +
      '<th style="font-size:11px;padding:3px 6px;">Original</th>' +
      '<th style="font-size:11px;padding:3px 6px;">Patché</th>' +
      '<th style="font-size:11px;padding:3px 6px;">Commentaire</th>' +
      '<th></th>' +
      '</tr></thead>';

    const rows = patches.map(function(p) {
      return '<tr>' +
        '<td><code>' + escapeHtml(typeof p.offset === 'number' ? '0x' + p.offset.toString(16) : String(p.offset)) + '</code></td>' +
        '<td><code>' + escapeHtml(p.original_bytes || '') + '</code></td>' +
        '<td><code>' + escapeHtml(p.patched_bytes || '') + '</code></td>' +
        '<td>' + escapeHtml(p.comment || '') + '</td>' +
        '<td><button class="patch-revert-btn" data-id="' + escapeHtml(String(p.id)) + '">Annuler</button></td>' +
      '</tr>';
    }).join('');

    const redoRows = redoPatches.map(function(p) {
      return '<tr>' +
        '<td><code>' + escapeHtml(typeof p.offset === 'number' ? '0x' + p.offset.toString(16) : String(p.offset)) + '</code></td>' +
        '<td><code>' + escapeHtml(p.original_bytes || '') + '</code></td>' +
        '<td><code>' + escapeHtml(p.patched_bytes || '') + '</code></td>' +
        '<td>' + escapeHtml(p.comment || '') + '</td>' +
        '<td><button class="patch-redo-btn" data-id="' + escapeHtml(String(p.id)) + '">Refaire</button></td>' +
        '</tr>';
    }).join('');

    const activeSection = patches.length > 0
      ? '<div class="patch-subsection"><div class="section-label" style="margin:0 0 6px 0;">Patches actifs</div><table>' + thead + '<tbody>' + rows + '</tbody></table></div>'
      : '<p class="hint" style="margin:6px 10px;">Aucun patch actif.</p>';
    const redoSection = redoPatches.length > 0
      ? '<div class="patch-subsection" style="margin-top:10px;"><div class="section-label" style="margin:0 0 6px 0;">Historique annulé</div><table>' + thead + '<tbody>' + redoRows + '</tbody></table></div>'
      : '';

    patchList.innerHTML = activeSection + redoSection;
    tabDataCache.patchList = { binaryPath: getStaticBinaryPath() };

    patchList.querySelectorAll('.patch-revert-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        const bp = getStaticBinaryPath();
        if (bp) vscode.postMessage({ type: 'hubRevertPatch', binaryPath: bp, patchId: btn.dataset.id });
      });
    });
    patchList.querySelectorAll('.patch-redo-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        const bp = getStaticBinaryPath();
        if (bp) vscode.postMessage({ type: 'hubRedoPatch', binaryPath: bp, patchId: btn.dataset.id });
      });
    });
    return;
  }
  if (msg.type === 'hubRevertPatchDone') {
    if (isStaleStaticBinaryResponse(msg, 'static-patch-revert')) return;
    const status = document.getElementById('hexPatchStatus');
    if (status) {
      status.className = 'hex-patch-status ' + (msg.ok ? 'ok' : 'error');
      status.textContent = msg.ok ? 'Patch annulé.' : `Error: ${msg.error || "Impossible d'annuler le patch."}`;
    }
    if (msg.ok) {
      const bp = getStaticBinaryPath();
      if (bp) {
        tabDataCache.hex = null;
        loadHexView(bp, hexCurrentOffset, hexCurrentLength);
      }
    }
    return;
  }
  if (msg.type === 'hubRedoPatchDone') {
    if (isStaleStaticBinaryResponse(msg, 'static-patch-redo')) return;
    const status = document.getElementById('hexPatchStatus');
    if (status) {
      status.className = 'hex-patch-status ' + (msg.ok ? 'ok' : 'error');
      status.textContent = msg.ok ? 'Patch réappliqué.' : `Error: ${msg.error || 'Impossible de réappliquer le patch.'}`;
    }
    if (msg.ok) {
      const bp = getStaticBinaryPath();
      if (bp) {
        tabDataCache.hex = null;
        loadHexView(bp, hexCurrentOffset, hexCurrentLength);
      }
    }
    return;
  }
  if (msg.type === 'hubStackFrame') {
    const binaryPath = msg.binaryPath || getStaticBinaryPath() || '';
    const activeSummary = getActiveContextSummary(window._lastDisasmAddr || decompileUiState.selectedAddr);
    const addr = normalizeHexAddress(msg.addr || activeSummary.functionAddr || activeSummary.addr);
    cacheStackFrame(binaryPath, addr, msg.result || {});
    const activeKey = getStackFrameCacheKey(activeSummary.binaryPath, activeSummary.functionAddr || activeSummary.addr);
    const receivedKey = getStackFrameCacheKey(binaryPath, addr);
    if (activeKey && activeKey === receivedKey) {
      renderStackFrame(msg.result);
    }
    if (activeKey && receivedKey && activeKey === receivedKey) {
      updateHexSelectionSummary(activeSummary.addr);
    }
    return;
  }
  if (msg.type === 'hubPickedFile') {
    const input = document.getElementById(msg.target);
    if (input) {
      input.value = msg.path;
      if (msg.target === 'dynamicSourcePath') {
        dynamicTraceInitState.sourcePath = String(msg.path || '').trim();
        dynamicTraceInitState.sourceEnrichmentEnabled = false;
        dynamicTraceInitState.sourceEnrichmentStatus = 'pending';
        dynamicTraceInitState.sourceEnrichmentMessage = '';
        if (dynamicSourceHint) dynamicSourceHint.textContent = buildDynamicSourceHintText(dynamicTraceInitState);
        updateArgvPayloadHint();
        requestRunTraceInit(null, binaryPathInput?.value?.trim() || '');
      }
      if (input.closest('#panel-options')) _scheduleSave();
    }
    return;
  }
  if (msg.type === 'hubSettings') {
    _applySettings(msg.settings);
    return;
  }
  if (msg.type === 'hubSettingsSaved') {
    return;
  }
  if (msg.type === 'hubScriptResult') {
    if (isStaleStaticBinaryResponse(msg, 'static-script')) return;
    const r = msg.result || {};
    const output = document.getElementById('scriptOutput');
    const status = document.getElementById('scriptStatus');
    const runBtn = document.getElementById('btnRunScript');
    if (runBtn) runBtn.removeAttribute('disabled');

    if (output) {
      let text = r.stdout || '';
      if (r.stderr) {
        text += r.stderr;
        output.classList.add('sc-output-error');
      } else {
        output.classList.remove('sc-output-error');
      }
      if (r.duration_ms != null) {
        text += '\n── ' + r.duration_ms + ' ms';
      }
      output.textContent = text;
    }
    if (status) status.textContent = r.ok ? '✓' : '✗ Erreur';
    return;
  }

  if (msg.type === 'hubScriptLoaded') {
    const editor = document.getElementById('scriptEditor');
    if (editor && msg.content != null) {
      editor.value = msg.content;
      _saveStorage({ scriptCode: msg.content });
    }
    return;
  }

  if (msg.type === 'hubScriptSaved') {
    const status = document.getElementById('scriptStatus');
    if (status) status.textContent = '💾 Sauvegardé';
    return;
  }
  if (msg.type === 'hubStructsDone' || msg.type === 'hubStructsSaved') {
    const data = msg.data || {};
    typedDataUiState.structSource = String(data.source || '');
    typedDataUiState.structsLoaded = true;
    typedDataUiState.loadingStructs = false;
    syncTypedDataStructSelect(data.structs || [], typedDataUiState.appliedStructName || undefined);
    if (data.error) {
      setTypedDataStructStatus(String(data.error), true);
      typedDataUiState.pendingEditorOpen = false;
      updateHexSelectionSummary();
      return;
    }
    if (typedDataUiState.pendingEditorOpen) {
      typedDataUiState.pendingEditorOpen = false;
      openTypedStructEditor(typedDataUiState.structSource);
      return;
    }
    if (msg.type === 'hubStructsSaved') {
      const structCount = Array.isArray(data.structs) ? data.structs.length : 0;
      setTypedDataStructStatus(`${structCount} type(s) C disponible(s).`);
      const bp = getStaticBinaryPath();
      const section = document.getElementById('typedDataSection')?.value;
      if (bp && section) {
        setStaticLoading('typedDataContent', 'Analyse des donn\u00e9es\u2026');
        vscode.postMessage(buildTypedDataRequest(bp, { page: 0 }));
      }
    }
    updateHexSelectionSummary();
    return;
  }
  if (msg.type === 'hubTypedStructPreviewDone') {
    if (isStaleStaticBinaryResponse(msg, 'static-typed-struct-preview')) return;
    const data = msg.data || {};
    const request = msg.request || {};
    typedDataUiState.hexStructPreview = {
      loading: false,
      structName: String(request.structName || ''),
      addr: normalizeHexAddress(request.structAddr || ''),
      error: data.error ? String(data.error) : '',
      appliedStruct: data.applied_struct || null,
    };
    updateHexSelectionSummary();
    return;
  }
  if (msg.type === 'hubTypedDataDone') {
    if (isStaleStaticBinaryResponse(msg, 'static-typed-data')) return;
    const container = document.getElementById('typedDataContent');
    if (!container) return;
    const {
      section,
      entries,
      sections,
      structs,
      type,
      page,
      page_size,
      total_entries,
      base_addr: baseAddr,
      size,
      endianness,
      ptr_size: ptrSize,
      bits,
      arch,
      applied_struct: appliedStruct,
      error,
    } = msg.data || {};
    const typedDataSummary = `
      <div class="typed-data-struct-summary typed-data-meta-summary">
        <strong>${escapeHtml(section || 'raw')}</strong>
        <span class="typed-data-struct-chip">type ${escapeHtml(type || 'auto')}</span>
        <span class="typed-data-struct-chip">base ${escapeHtml(baseAddr || '0x0')}</span>
        <span class="typed-data-struct-chip">taille ${escapeHtml(String(size || 0))} o</span>
        ${arch ? `<span class="typed-data-struct-chip">arch ${escapeHtml(_displayRawArchName(String(arch)))}</span>` : ''}
        ${bits ? `<span class="typed-data-struct-chip">${escapeHtml(String(bits))}-bit</span>` : ''}
        ${endianness ? `<span class="typed-data-struct-chip">${escapeHtml(_displayEndianName(String(endianness)))}</span>` : ''}
        ${ptrSize ? `<span class="typed-data-struct-chip">ptr ${escapeHtml(String(ptrSize))} o</span>` : ''}
      </div>
    `;
    const sectionSel = document.getElementById('typedDataSection');
    const structOffsetInput = document.getElementById('typedDataStructOffset');
    if (sectionSel && sections && sections.length > 0 && sectionSel.options.length <= 1) {
      sections.forEach(s => sectionSel.add(new Option(s, s)));
    }
    if (sectionSel && section) sectionSel.value = section;
    syncTypedDataStructSelect(structs || [], appliedStruct?.name || document.getElementById('typedDataStructSelect')?.value || '');
    if (error) {
      setTypedDataStructStatus(String(error), true);
      container.innerHTML = '<p class="hint">' + escapeHtml(error) + '</p>';
      return;
    }
    if (appliedStruct) {
      typedDataUiState.appliedStructName = String(appliedStruct.name || '');
      typedDataUiState.appliedStructOffset = '0x' + Number(appliedStruct.offset || 0).toString(16);
      typedDataUiState.appliedStructAddr = normalizeHexAddress(appliedStruct.addr || '');
      typedDataUiState.hexStructName = typedDataUiState.appliedStructName;
      const activeBinaryPath = getStaticBinaryPath();
      if (activeBinaryPath) {
        vscode.postMessage({
          type: 'hubSaveTypedStructRef',
          binaryPath: activeBinaryPath,
          appliedStruct,
        });
      }
      if (structOffsetInput) structOffsetInput.value = typedDataUiState.appliedStructOffset;
      setTypedDataStructStatus(
        `${String(appliedStruct.kind || 'struct')} ${typedDataUiState.appliedStructName} @ +${typedDataUiState.appliedStructOffset}`,
        false,
      );
      const summary = `
        <div class="typed-data-struct-summary">
          <strong>${escapeHtml(appliedStruct.name || '')}</strong>
          <span class="typed-data-struct-chip">${escapeHtml(String(appliedStruct.kind || 'struct'))}</span>
          <span class="typed-data-struct-chip">addr ${escapeHtml(appliedStruct.addr || '')}</span>
          <span class="typed-data-struct-chip">section ${escapeHtml(appliedStruct.section || section || '')}</span>
          <span class="typed-data-struct-chip">taille ${escapeHtml(String(appliedStruct.size || 0))} o</span>
          <span class="typed-data-struct-chip">align ${escapeHtml(String(appliedStruct.align || 1))}</span>
          <span class="typed-data-struct-chip">${escapeHtml(String((appliedStruct.fields || []).length))} champ(s)</span>
          ${typedDataUiState.appliedStructAddr ? `<span class="typed-data-quick-chip">sélection ${escapeHtml(typedDataUiState.appliedStructAddr)}</span>` : ''}
        </div>
      `;
      const rows = (appliedStruct.fields || []).map((field) => {
        const decodedCell = field.tag === 'ptr'
          ? '<code class="addr-link" data-addr="' + escapeHtml(field.decoded || '') + '">' + escapeHtml(field.decoded || '') + '</code>'
          : '<span>' + escapeHtml(field.decoded || '') + '</span>';
        const fieldAddr = normalizeHexAddress(field.addr || '');
        const fieldStart = parseNumericAddress(fieldAddr);
        const fieldSize = normalizeSpanLength(field.size || 1);
        const fieldEnd = Number.isFinite(fieldStart) ? `0x${(fieldStart + fieldSize - 1).toString(16)}` : fieldAddr;
        return '<tr class="typed-data-row" data-range-start="' + escapeHtml(fieldAddr || '') + '" data-range-end="' + escapeHtml(fieldEnd || fieldAddr || '') + '">' +
          '<td><code>' + escapeHtml(field.field_name || '') + '</code></td>' +
          '<td><code>' + escapeHtml(field.field_type || '') + '</code></td>' +
          '<td><code class="addr-link" data-hex-addr="' + escapeHtml(field.addr || '') + '" data-span="' + escapeHtml(String(field.size || 1)) + '">0x' + escapeHtml(Number(field.offset || 0).toString(16)) + '</code></td>' +
          '<td><code class="addr-link" data-addr="' + escapeHtml(field.addr || '') + '" data-span="' + escapeHtml(String(field.size || 1)) + '">' + escapeHtml(field.addr || '') + '</code></td>' +
          '<td><code style="font-size:11px">' + escapeHtml(field.hex || '') + '</code></td>' +
          '<td>' + decodedCell + '</td>' +
          '</tr>';
      }).join('');
      container.innerHTML = typedDataSummary + summary +
        '<table class="data-table"><thead><tr>' +
        '<th>Champ</th><th>Type</th><th>Offset</th><th>Adresse</th><th>Hex</th><th>Valeur</th>' +
        '</tr></thead><tbody>' + rows + '</tbody></table>';
      container.querySelectorAll('.addr-link[data-addr]').forEach((el) => {
        if (!el.dataset.addr) return;
        el.style.cursor = 'pointer';
        el.addEventListener('click', () => {
          const span = normalizeSpanLength(el.dataset.span || 1);
          syncTypedDataEntrySelection({ addr: el.dataset.addr, size: span }, { openDisasm: true });
        });
      });
      container.querySelectorAll('.addr-link[data-hex-addr]').forEach((el) => {
        if (!el.dataset.hexAddr) return;
        el.style.cursor = 'pointer';
        el.addEventListener('click', () => {
          const span = normalizeSpanLength(el.dataset.span || 1);
          syncTypedDataEntrySelection({ addr: el.dataset.hexAddr, size: span }, { openHex: true });
        });
      });
      updateTypedDataActiveSelection(window._lastDisasmAddr, hexSelectionModel.spanLength, { reveal: false });
      return;
    }
    typedDataUiState.appliedStructName = '';
    typedDataUiState.appliedStructAddr = '';
    setTypedDataStructStatus('');
    const entryList = entries || [];
    if (entryList.length === 0) {
      container.innerHTML = '<p class="hint">Section vide ou donn\u00e9es insuffisantes.</p>';
      return;
    }
    const TAG_COLORS = {
      string: '#88d8ff', wstring: '#88d8ff', ptr: '#88c0d0',
      u8: '#d8dee9', u16: '#d8dee9', u32: '#d8dee9', u64: '#d8dee9',
      f32: '#ebcb8b', f64: '#ebcb8b',
    };
    const currentPage = page || 0;
    const totalPages = Math.ceil((total_entries || entryList.length) / (page_size || 128));
    const paginHtml = totalPages > 1
      ? '<div class="typed-data-pagination">' +
        '<button id="btnTypedPrev" class="btn btn-sm"' + (currentPage === 0 ? ' disabled' : '') + '>&#9664;</button>' +
        '<span style="font-size:12px">Page ' + (currentPage + 1) + ' / ' + totalPages + '</span>' +
        '<button id="btnTypedNext" class="btn btn-sm"' + (currentPage >= totalPages - 1 ? ' disabled' : '') + '>&#9654;</button>' +
        '</div>'
      : '';
    const rows = entryList.map(e => {
      const tagColor = TAG_COLORS[e.tag] ? 'color:' + TAG_COLORS[e.tag] : '';
      const decodedCell = e.tag === 'ptr'
        ? '<code class="addr-link" data-addr="' + escapeHtml(e.decoded || '') + '" style="' + tagColor + '">' + escapeHtml(e.decoded || '') + '</code>'
        : '<span style="' + tagColor + '">' + escapeHtml(e.decoded || '') + '</span>';
      const span = getTypedDataEntrySpanLength(e);
      const entryAddr = normalizeHexAddress(e.addr || '');
      const entryStart = parseNumericAddress(entryAddr);
      const entryEnd = Number.isFinite(entryStart) ? `0x${(entryStart + span - 1).toString(16)}` : entryAddr;
      return '<tr class="typed-data-row" data-range-start="' + escapeHtml(entryAddr || '') + '" data-range-end="' + escapeHtml(entryEnd || entryAddr || '') + '">' +
        '<td><code class="addr-link" data-hex-addr="' + escapeHtml(e.addr || '') + '" data-span="' + escapeHtml(String(span)) + '">' + escapeHtml(e.offset !== undefined ? '0x' + Number(e.offset).toString(16) : '') + '</code></td>' +
        '<td><code class="addr-link" data-addr="' + escapeHtml(e.addr || '') + '" data-span="' + escapeHtml(String(span)) + '">' + escapeHtml(e.addr || '') + '</code></td>' +
        '<td><code style="font-size:11px">' + escapeHtml(e.hex || '') + '</code></td>' +
        '<td>' + decodedCell + '</td>' +
        '</tr>';
    }).join('');
    container.innerHTML = typedDataSummary + paginHtml +
      '<table class="data-table"><thead><tr>' +
      '<th>Offset</th><th>Adresse</th><th>Hex</th><th>Valeur</th>' +
      '</tr></thead><tbody>' + rows + '</tbody></table>' + paginHtml;
    container.querySelectorAll('.addr-link[data-addr]').forEach(el => {
      if (!el.dataset.addr) return;
      el.style.cursor = 'pointer';
      el.addEventListener('click', () => {
        const span = normalizeSpanLength(el.dataset.span || 1);
        syncTypedDataEntrySelection({ addr: el.dataset.addr, size: span }, { openDisasm: true });
      });
    });
    container.querySelectorAll('.addr-link[data-hex-addr]').forEach(el => {
      if (!el.dataset.hexAddr) return;
      el.style.cursor = 'pointer';
      el.addEventListener('click', () => {
        const span = normalizeSpanLength(el.dataset.span || 1);
        syncTypedDataEntrySelection({ addr: el.dataset.hexAddr, size: span }, { openHex: true });
      });
    });
    updateTypedDataActiveSelection(window._lastDisasmAddr, hexSelectionModel.spanLength, { reveal: false });
    const bp = getStaticBinaryPath();
    container.querySelectorAll('#btnTypedPrev').forEach(btn => {
      btn.addEventListener('click', () => {
        if (currentPage > 0)
          vscode.postMessage(buildTypedDataRequest(bp, { page: currentPage - 1, valueType: type || 'auto' }));
      });
    });
    container.querySelectorAll('#btnTypedNext').forEach(btn => {
      btn.addEventListener('click', () => {
        if (currentPage < totalPages - 1)
          vscode.postMessage(buildTypedDataRequest(bp, { page: currentPage + 1, valueType: type || 'auto' }));
      });
    });
    return;
  }
  if (msg.type === 'hubExceptionHandlersDone') {
    if (isStaleStaticBinaryResponse(msg, 'static-exceptions')) return;
    const renderStarted = performance.now();
    const container = document.getElementById('exceptionsContent');
    const countEl = document.getElementById('exceptionsCount');
    if (!container) return;
    const { entries, error } = msg.data || {};
    if (error) {
      container.innerHTML = '<p class="hint">' + escapeHtml(error) + '</p>';
      reportStaticWebviewPerf('exceptions.render', renderStarted, { error: true });
      return;
    }
    const list = entries || [];
    if (list.length === 0) {
      container.innerHTML = '<p class="hint">Aucun gestionnaire d\'exception dans ce binaire.</p>';
      if (countEl) countEl.textContent = '';
      reportStaticWebviewPerf('exceptions.render', renderStarted, { entries: 0, empty: true });
      return;
    }
    const badgeClass = (t) =>
      t === 'SEH' ? 'exc-badge-seh' : (t && t.includes('C++')) ? 'exc-badge-cpp' : 'exc-badge-dwarf';
    function renderExc(filterStr) {
      const f = (filterStr || '').toLowerCase();
      const visible = f
        ? list.filter(e => (e.func_start || '').toLowerCase().includes(f) ||
                           (e.handler_type || '').toLowerCase().includes(f))
        : list;
      if (countEl) countEl.textContent = visible.length + ' / ' + list.length;
      const rows = visible.map(e =>
        '<tr>' +
        '<td><code class="addr-link" data-addr="' + escapeHtml(e.func_start || '') + '">' + escapeHtml(e.func_start || '\u2014') + '</code></td>' +
        '<td><code>' + escapeHtml(e.func_end || '\u2014') + '</code></td>' +
        '<td><span class="exc-badge ' + badgeClass(e.handler_type) + '">' + escapeHtml(e.handler_type || '\u2014') + '</span></td>' +
        '<td>' + (e.handler ? '<code class="addr-link" data-addr="' + escapeHtml(e.handler) + '">' + escapeHtml(e.handler) + '</code>' : '\u2014') + '</td>' +
        '</tr>'
      ).join('');
      container.innerHTML =
        '<table class="data-table"><thead><tr>' +
        '<th>Fonction</th><th>Fin</th><th>Type</th><th>Handler</th>' +
        '</tr></thead><tbody>' + rows + '</tbody></table>';
      container.querySelectorAll('.addr-link[data-addr]').forEach(el => {
        if (!el.dataset.addr) return;
        el.style.cursor = 'pointer';
        el.addEventListener('click', () =>
          vscode.postMessage({ type: 'hubGoToAddress', addr: el.dataset.addr, binaryPath: getStaticBinaryPath() }));
      });
      reportStaticWebviewPerf('exceptions.render', renderStarted, {
        entries: list.length,
        visible: visible.length,
        filterTextLength: String(filterStr || '').length,
      });
    }
    const searchEl = document.getElementById('exceptionsSearch');
    const currentSearch = searchEl ? searchEl.value : '';
    if (searchEl) {
      const newEl = searchEl.cloneNode(true);
      searchEl.parentNode.replaceChild(newEl, searchEl);
      newEl.addEventListener('input', () => renderExc(newEl.value));
    }
    renderExc(currentSearch);
    return;
  }
  if (msg.type === 'hubPeResourcesDone') {
    if (isStaleStaticBinaryResponse(msg, 'static-pe-resources')) return;
    const renderStarted = performance.now();
    const container = document.getElementById('peResourcesContent');
    if (!container) return;
    const { resources, error, applicable, message, format } = msg.data || {};
    if (error) {
      const p = document.createElement('p');
      p.className = 'hint';
      p.textContent = error;
      container.replaceChildren(p);
      reportStaticWebviewPerf('pe.resources.render', renderStarted, { error: true });
      return;
    }
    if (applicable === false) {
      const p = document.createElement('p');
      p.className = 'hint';
      p.textContent = message || `Cette vue s'applique uniquement aux binaires PE${format ? ` (${format})` : ''}.`;
      container.replaceChildren(p);
      reportStaticWebviewPerf('pe.resources.render', renderStarted, {
        applicable: false,
        format: String(format || ''),
      });
      return;
    }
    if (!resources || resources.length === 0) {
      const p = document.createElement('p');
      p.className = 'hint';
      p.textContent = 'Aucune ressource dans ce binaire.';
      container.replaceChildren(p);
      reportStaticWebviewPerf('pe.resources.render', renderStarted, { resources: 0, empty: true });
      return;
    }
    // Group by type
    const byType = {};
    for (const r of resources) {
      if (!byType[r.type]) byType[r.type] = [];
      byType[r.type].push(r);
    }

    // Layout: filtre + arbre gauche / détail droite
    const layout = document.createElement('div');
    layout.className = 'resource-layout';

    const treePaneEl = document.createElement('div');
    treePaneEl.className = 'resource-tree-pane';

    const filterWrap = document.createElement('div');
    filterWrap.className = 'resource-filter-wrap';
    const filterInput = document.createElement('input');
    filterInput.type = 'text';
    filterInput.className = 'resource-filter';
    filterInput.placeholder = 'Filtrer (type, ID\u2026)';
    filterInput.spellcheck = false;
    filterWrap.appendChild(filterInput);
    treePaneEl.appendChild(filterWrap);

    const treeEl = document.createElement('div');
    treeEl.className = 'resource-tree';
    treePaneEl.appendChild(treeEl);

    const detailEl = document.createElement('div');
    detailEl.className = 'resource-detail';
    const detailPlaceholder = document.createElement('p');
    detailPlaceholder.className = 'hint';
    detailPlaceholder.textContent = 'S\u00e9lectionne une ressource pour voir le d\u00e9tail.';
    detailEl.appendChild(detailPlaceholder);

    layout.appendChild(treePaneEl);
    layout.appendChild(detailEl);

    let activeItem = null;

    function buildResourceTree(filterStr) {
      const f = (filterStr || '').toLowerCase().trim();
      treeEl.textContent = '';
      for (const [type, items] of Object.entries(byType)) {
        const filtered = f
          ? items.filter((r) =>
              type.toLowerCase().includes(f) ||
              String(r.id).toLowerCase().includes(f) ||
              String(r.lang).toLowerCase().includes(f)
            )
          : items;
        if (!filtered.length) continue;

        const typeRow = document.createElement('div');
        typeRow.className = 'resource-tree-type';
        const itemsDiv = document.createElement('div');
        itemsDiv.className = 'resource-tree-items';
        let open = !!f;
        const setLabel = (o) => {
          typeRow.textContent = (o ? '\u25BE ' : '\u25B8 ') + type + ' (' + filtered.length + ')';
        };
        setLabel(open);
        itemsDiv.style.display = open ? '' : 'none';
        typeRow.addEventListener('click', () => {
          open = !open;
          itemsDiv.style.display = open ? '' : 'none';
          setLabel(open);
        });

        filtered.forEach((r) => {
          const item = document.createElement('div');
          item.className = 'resource-tree-item';
          item.textContent = 'ID\u00a0' + r.id + '\u00b7 Lang\u00a0' + r.lang + '\u00b7 ' + r.size + '\u00a0o';
          item.addEventListener('click', () => {
            if (activeItem) activeItem.classList.remove('is-active');
            item.classList.add('is-active');
            activeItem = item;
            if (typeof renderPeResourceDetail === 'function') {
              renderPeResourceDetail(r, detailEl);
            } else {
              let text = 'Type: ' + r.type + '\nID: ' + r.id + '\nLang: ' + r.lang + '\nSize: ' + r.size + ' octets\n\n';
              if (r.decoded) text += 'Decoded:\n' + JSON.stringify(r.decoded, null, 2) + '\n\n';
              text += 'Hex preview:\n' + (r.hex_preview || '\u2014');
              detailEl.textContent = text;
            }
          });
          itemsDiv.appendChild(item);
        });
        treeEl.appendChild(typeRow);
        treeEl.appendChild(itemsDiv);
      }
    }

    buildResourceTree('');
    filterInput.addEventListener('input', () => buildResourceTree(filterInput.value));
    container.replaceChildren(layout);
    reportStaticWebviewPerf('pe.resources.render', renderStarted, {
      resources: resources.length,
      groups: Object.keys(byType).length,
    });
    return;
  }

  // ── AI Providers ────────────────────────────────────────────────────────
  if (msg.type === 'hubAiProvidersResult') {
    var aiData = msg.data;
    if (aiData && Array.isArray(aiData.providers)) {
      _renderAiProviders(aiData);
      // Sync Ollama base URL into state
      var ollamaProvider = aiData.providers.find(function(p) { return p.name === 'ollama'; });
      if (ollamaProvider && ollamaProvider.base_url && typeof ollamaUiState !== 'undefined') {
        ollamaUiState.baseUrl = ollamaProvider.base_url;
      }
      // Also populate model selects in the Ollama/MCP chat panels
      if (typeof injectCloudProviderModels === 'function') {
        injectCloudProviderModels(aiData.providers);
      }
    } else if (aiData && aiData.error) {
      var errEl = document.getElementById('aiProvidersState');
      if (errEl) {
        while (errEl.firstChild) { errEl.removeChild(errEl.firstChild); }
        var ep = document.createElement('p');
        ep.className = 'settings-field-hint';
        ep.textContent = 'Erreur : ' + String(aiData.error);
        errEl.appendChild(ep);
      }
    }
    return;
  }
  if (msg.type === 'hubAiProviderDefaultSaved') {
    var savedDefault = String(msg.data?.default_provider || '').trim();
    if (savedDefault) {
      var defaultSelect = document.getElementById('aiDefaultProvider');
      if (defaultSelect) defaultSelect.title = `Provider automatique enregistré : ${savedDefault}`;
    }
    return;
  }
});
window.addEventListener('message', (event) => {
  const msg = event.data;
  if (!msg?.type || msg.type === 'hubUiConsumed') return;
  let consumed = false;
  const acknowledge = () => {
    if (consumed) return;
    consumed = true;
    vscode.postMessage({
      type: 'hubUiConsumed',
      responseType: String(msg.type),
    });
  };
  if (typeof requestAnimationFrame === 'function') {
    requestAnimationFrame(() => requestAnimationFrame(acknowledge));
    setTimeout(acknowledge, 250);
  } else {
    setTimeout(acknowledge, 0);
  }
});
}
