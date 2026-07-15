
function parsePayloadExpressionPreview(input) {
  return hubPayloadCore.parsePayloadExpressionPreview(input);
}

function bytesToCompactHex(bytes) {
  return hubPayloadCore.bytesToCompactHex(bytes);
}

function bytesToSpacedHex(bytes) {
  return hubPayloadCore.bytesToSpacedHex(bytes);
}

function bytesToEscapedHex(bytes) {
  return hubPayloadCore.bytesToEscapedHex(bytes);
}

function buildPayloadEndianHint(input) {
  return hubPayloadCore.buildPayloadEndianHint(input);
}

function updateArgvPayloadHint() {
  if (!argvPayloadHint) return;
  if (getDynamicPayloadMode() === 'pwntools_script') {
    const entries = getPwntoolsCaptureEntries();
    const selectedCapture = pwntoolsScriptController?.getSelectedCapture?.() || null;
    const selected = entries.find((entry) => entry.id === selectedCapture?.captureId) || entries[0] || null;
    if (!selected) {
      argvPayloadHint.textContent = 'Analyse un script pwntools pour extraire un payload.';
      return;
    }
    const target = selectedCapture?.target || selected.targetHint || 'stdin';
    argvPayloadHint.textContent = `Capture pwntools sélectionnée: ${selected.size} byte(s). Cible effective: ${dynamicPayloadTargetLabel(target)}.`;
    return;
  }
  const raw = payloadBuilderInput?.value ?? '';
  const trimmed = raw.trim();
  const targetHint = buildDynamicPayloadTargetHint();
  const currentTarget = dynamicPayloadTargetLabel(getDynamicEffectivePayloadTarget());
  if (!trimmed) {
    argvPayloadHint.textContent = targetHint;
    return;
  }
  try {
    const helper = getExploitHelperApi();
    const resolved = helper?.buildPayload
      ? helper.buildPayload(trimmed, getDynamicPayloadBuilderLevel(), {
        arch: getDynamicResolvedArch(),
        endian: exploitHelperController?.getEndian?.() || exploitHelperEndian?.value || 'little',
        badchars: exploitHelperController?.getBadchars?.() || exploitHelperBadchars?.value || '',
        targetMode: getDynamicPayloadTargetMode(),
      })
      : null;
    const parsed = resolved ? { bytes: resolved.size || 0 } : parsePayloadExpressionPreview(trimmed);
    const endianHint = buildPayloadEndianHint(trimmed);
    argvPayloadHint.textContent = `Payload courant: ${parsed.bytes} byte(s). Cible effective: ${currentTarget}. ${targetHint}${endianHint ? ` ${endianHint}` : ''}`;
  } catch (_) {
    argvPayloadHint.textContent = 'Expression payload invalide.';
  }
}

function requestDynamicTraceHistory() {
  if (payloadHistoryController?.refreshHistory) {
    payloadHistoryController.refreshHistory();
    return;
  }
  vscode.postMessage({ type: 'requestDynamicTraceHistory' });
}

function renderDynamicTraceHistory() {
  if (payloadHistoryController?.renderHistory) {
    payloadHistoryController.renderHistory();
  }
}

function applyRunTraceInit(msg) {
  if (runTraceController?.applyRunTraceInit) {
    runTraceController.applyRunTraceInit(msg);
  }
}

function getAnnotatedFunctionDisplayName(addr, fallbackName = '') {
  const normalized = typeof normalizeHexAddress === 'function' ? normalizeHexAddress(addr) : String(addr || '').trim();
  const annotatedName = String(window._annotations?.[normalized]?.name || '').trim();
  return annotatedName || String(fallbackName || '').trim();
}

function populateDecompileSelect(symbols) {
  const sel = document.getElementById('decompileAddrSelect');
  if (!sel) return;
  const previousValue = sel.value || decompileUiState.selectedAddr || '';
  const entriesByAddr = new Map();
  const appendEntry = (addr, name, sourceRank = 0) => {
    const normalized = normalizeHexAddress(addr);
    if (!normalized) return;
    const current = entriesByAddr.get(normalized);
    const displayName = getAnnotatedFunctionDisplayName(normalized, name);
    if (!current || sourceRank > current.sourceRank || (!current.name && displayName)) {
      entriesByAddr.set(normalized, {
        addr: normalized,
        name: displayName,
        sourceRank,
      });
    }
  };
  sel.replaceChildren(Object.assign(document.createElement('option'), { value: '', textContent: '⊞ Vue globale' }));
  (symbols || []).filter(s =>
    s.type === 'T' &&
    s.addr && s.addr !== '0x0' &&
    parseInt(s.addr, 16) >= 0x1000 &&
    s.name && !s.name.includes('/')
  ).forEach(s => {
    appendEntry(s.addr, s.name, 30);
  });
  (window.functionListCache || []).forEach((fn) => {
    appendEntry(fn.addr, fn.name, 20);
  });
  (window.discoveredFunctionsCache || []).forEach((fn) => {
    appendEntry(fn.addr, fn.name, 10);
  });
  Array.from(entriesByAddr.values())
    .sort((a, b) => (parseNumericAddress(a.addr) || 0) - (parseNumericAddress(b.addr) || 0))
    .forEach((entry) => {
    const opt = document.createElement('option');
    opt.value = entry.addr;
    opt.dataset.name = entry.name || '';
    opt.textContent = `${entry.addr}  ${entry.name || ''}`.trim();
    sel.appendChild(opt);
  });
  const optionValues = Array.from(sel.options).map((opt) => opt.value);
  if (previousValue && optionValues.includes(previousValue)) {
    sel.value = previousValue;
  } else if (window._lastDisasmAddr) {
    syncDecompileSelection(window._lastDisasmAddr, { forceContext: true });
  }
  decompileUiState.selectedAddr = sel.value || '';
}

function ensureDecompileSelectionSourcesLoaded(binaryPath) {
  const bp = binaryPath || getStaticBinaryPath();
  if (!bp) return;
  if (tabDataCache.sections?.binaryPath !== bp) {
    postBinaryAwareMessage('hubLoadSections', { binaryPath: bp });
  }
  if (tabDataCache.symbols?.binaryPath !== bp) {
    postBinaryAwareMessage('hubLoadSymbols', { binaryPath: bp });
  }
  if (isRawBinarySelected()) {
    if (tabDataCache.discovered?.binaryPath !== bp) {
      postBinaryAwareMessage('hubLoadDiscoveredFunctions', { binaryPath: bp });
    }
    return;
  }
  if (tabDataCache.discovered?.binaryPath !== bp) {
    postBinaryAwareMessage('hubLoadFunctions', { binaryPath: bp });
  }
}

// Local path specs come from decompilers.json via _meta — no hardcoded entries.
const _DECOMPILER_LOCAL_PATH_SPECS = [];

// Tracks backend availability returned by the backend registry.
let _decompilerAvailability = {};
let _decompilerMeta = {};
// Number of available decompilers seen this session — used to auto-reset source to
// 'auto' when more decompilers become available (e.g. after a previous broken state
// had only RetDec working, persisting 'retdec' in localStorage).
let _decompilerSessionAvailableCount = 0;
let _selectedDecompilerCardId = '';
let _decompilerLocalUiState = {
  visibilityById: {},
};

function _getConfiguredDecompilerProvider() {
  return String(_settingsCache?.decompilerProvider || 'auto').trim() || 'auto';
}

function _getSelectedDecompilerChoice() {
  return String(_loadStorage().decompileSource || 'auto').trim() || 'auto';
}

function _updateDecompilerActionButtons() {
  // Les boutons Modifier/Supprimer sont maintenant directement dans chaque card.
  // On garde seulement la mise à jour des boutons globaux (Ajouter, Tester).
  // Les boutons btnDecompilerEdit et btnDecompilerRemove sont cachés s'ils existent encore.
  const editBtn = document.getElementById('btnDecompilerEdit');
  const removeBtn = document.getElementById('btnDecompilerRemove');
  if (editBtn) editBtn.style.display = 'none';
  if (removeBtn) removeBtn.style.display = 'none';
}

function _getLocalPathSpecForDecompiler(id) {
  const normalized = String(id || '').trim().toLowerCase();
  return _DECOMPILER_LOCAL_PATH_SPECS.find((spec) => spec.id === normalized) || null;
}

function _describeLocalDetectionHint(id, localSpec, localPathValue) {
  if (!localSpec) return '';
  if (localPathValue) return "Le chemin configuré est prioritaire sur l'auto-détection.";
  const normalized = String(id || '').trim().toLowerCase();
  if (normalized === 'ghidra') {
    return "Auto-détection: GHIDRA_INSTALL_DIR / GHIDRA_HOME, puis emplacements usuels selon l'OS.";
  }
  if (normalized === 'retdec') {
    return "Auto-détection: PATH puis RETDEC_INSTALL_DIR.";
  }
  return "Auto-détection via variables d'environnement, PATH et chemins usuels.";
}

function populateDecompilerProfiles(available) {
  const meta = available?._meta || {};
  const labels = meta.labels || {};
  const dockerImages = meta.docker_images || {};
  _decompilerMeta = meta;
  _decompilerAvailability = Object.fromEntries(
    Object.entries(available || {}).filter(([key]) => !key.startsWith('_'))
  );
  const select = document.getElementById('decompileSourceSelect');
  if (!select) return;
  const previous = _getSelectedDecompilerChoice();
  // Ordre de déclaration dans decompilers.json (préservé par _load_decompilers)
  const entries = Object.keys(_decompilerAvailability);
  select.replaceChildren();
  select.appendChild(Object.assign(document.createElement('option'), {
    value: 'auto',
    textContent: 'Auto',
  }));
  entries.forEach((id) => {
    const option = document.createElement('option');
    const label = labels[id] || id;
    const availableNow = !!_decompilerAvailability[id];
    option.value = id;
    option.textContent = availableNow ? label : `${label} indisponible`;
    option.disabled = !availableNow;
    select.appendChild(option);
  });
  const titleParts = [`Provider ${_getConfiguredDecompilerProvider()}`];
  const selectedId = previous !== 'auto' ? previous : '';
  if (selectedId && dockerImages[selectedId]) titleParts.push(`Docker ${dockerImages[selectedId]}`);
  select.title = titleParts.filter(Boolean).join(' • ');
  const validValues = new Set(Array.from(select.options).filter((opt) => !opt.disabled).map((opt) => opt.value));
  const availableCount = validValues.size - 1; // exclude 'auto'
  let resolved = validValues.has(previous) ? previous : 'auto';
  // If more decompilers became available than seen so far this session, reset to auto.
  // This clears a stale non-auto choice that was saved when fewer decompilers worked.
  if (availableCount > _decompilerSessionAvailableCount && resolved !== 'auto') {
    resolved = 'auto';
  }
  if (availableCount > _decompilerSessionAvailableCount) _decompilerSessionAvailableCount = availableCount;
  select.value = resolved;
  if (select.value !== previous) _saveStorage({ decompileSource: select.value });
  _updateDecompilerActionButtons();
}

function updateDecompileSearchUi(count = null) {
  const input = document.getElementById('decompileSearchInput');
  const label = document.getElementById('decompileSearchCount');
  const prevBtn = document.getElementById('btnDecompileSearchPrev');
  const nextBtn = document.getElementById('btnDecompileSearchNext');
  if (input && input.value !== decompileUiState.searchQuery) input.value = decompileUiState.searchQuery || '';
  const resolvedCount = typeof count === 'number'
    ? count
    : document.querySelectorAll('#decompileContent .decompile-search-hit').length;
  if (prevBtn) prevBtn.disabled = resolvedCount <= 1;
  if (nextBtn) nextBtn.disabled = resolvedCount <= 1;
  if (!label) return;
  const query = String(decompileUiState.searchQuery || '').trim();
  if (!query) {
    if (prevBtn) prevBtn.disabled = true;
    if (nextBtn) nextBtn.disabled = true;
    label.textContent = 'Recherche inactive';
    return;
  }
  if (typeof resolvedCount === 'number') {
    if (resolvedCount <= 0) {
      if (prevBtn) prevBtn.disabled = true;
      if (nextBtn) nextBtn.disabled = true;
      label.textContent = 'Aucun hit';
      return;
    }
    const active = Number.isFinite(decompileUiState.activeSearchHit) && decompileUiState.activeSearchHit >= 0
      ? decompileUiState.activeSearchHit + 1
      : 1;
    label.textContent = `${Math.min(active, resolvedCount)}/${resolvedCount}`;
    return;
  }
  label.textContent = 'Recherche…';
}

function isTypingElement(node) {
  const el = node?.nodeType === 1 ? node : node?.parentElement;
  if (!el) return false;
  const tag = String(el.tagName || '').toUpperCase();
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || Boolean(el.isContentEditable);
}

function focusDecompileSearchInput(opts = {}) {
  const input = document.getElementById('decompileSearchInput');
  if (!input) return false;
  input.focus();
  if (opts.select !== false && typeof input.select === 'function') input.select();
  return true;
}

function _setActiveDecompilerSource(source) {
  const normalized = String(source || 'auto').trim() || 'auto';
  const select = document.getElementById('decompileSourceSelect');
  if (select && select.value !== normalized) select.value = normalized;
  _saveStorage({ decompileSource: normalized });
  _updateDecompilerActionButtons();
}

function _getActiveDecompilerSource() {
  const select = document.getElementById('decompileSourceSelect');
  return String(select?.value || _loadStorage().decompileSource || 'auto').trim() || 'auto';
}

function _getRequestedDecompilerForQuality(_quality) {
  return decompileUiState.forcedDecompiler || '';
}

function formatDecompilerPillLabel(name) {
  const normalized = String(name || '').trim();
  const known = {
    angr: 'Angr',
    ghidra: 'Ghidra',
    retdec: 'RetDec',
  };
  return known[normalized.toLowerCase()] || (normalized.charAt(0).toUpperCase() + normalized.slice(1));
}

function appendDecompilerPillStatus(pill, info) {
  if (!pill || !info) return;
  if (info.status === 'running') {
    const spinner = document.createElement('span');
    spinner.className = 'decompile-pill-spinner';
    spinner.setAttribute('aria-hidden', 'true');
    pill.appendChild(spinner);
    const status = document.createElement('span');
    status.className = 'decompile-pill-status';
    status.textContent = 'En cours';
    pill.appendChild(status);
    return;
  }
  if (info.status === 'error') {
    const status = document.createElement('span');
    status.className = 'decompile-pill-status decompile-pill-status--error';
    status.textContent = 'Erreur';
    pill.appendChild(status);
    return;
  }
  if (info.status === 'done' && info.score != null) {
    const score = document.createElement('span');
    score.className = 'decompile-pill-score';
    score.textContent = String(info.score);
    pill.appendChild(score);
  }
}

function renderDecompilePills(container, pillStatuses, bestDecompiler, forcedDecompiler) {
  while (container.firstChild) container.removeChild(container.firstChild);
  const autoSelected = forcedDecompiler === '';
  // Auto pill
  const autoPill = document.createElement('button');
  autoPill.type = 'button';
  autoPill.className = 'decompile-pill' + (autoSelected ? ' decompile-pill--selected' : '');
  const autoLabel = document.createElement('span');
  autoLabel.className = 'decompile-pill-label';
  autoLabel.textContent = 'Auto';
  autoPill.appendChild(autoLabel);
  if (bestDecompiler && autoSelected) {
    const best = document.createElement('span');
    best.className = 'decompile-pill-status';
    best.textContent = formatDecompilerPillLabel(bestDecompiler);
    autoPill.appendChild(best);
  }
  autoPill.title = autoSelected
    ? 'Mode auto actif'
    : 'Revenir au mode auto (meilleur résultat)';
  autoPill.addEventListener('click', () => {
    decompileUiState.forcedDecompiler = '';
    const best = decompileUiState.bestDecompiler;
    if (best && decompileUiState.payloads[best]) {
      const c = document.getElementById('decompileContent');
      if (c) renderDecompilePayload(c, decompileUiState.payloads[best]);
    }
    _refreshDecompilePills();
  });
  container.appendChild(autoPill);
  // Per-decompiler pills
  for (const [name, info] of Object.entries(pillStatuses)) {
    const pill = document.createElement('button');
    pill.type = 'button';
    const isBest = name === bestDecompiler && autoSelected;
    const isForced = name === forcedDecompiler;
    let cls = 'decompile-pill';
    if (info.status === 'running') cls += ' decompile-pill--running';
    else if (info.status === 'error') cls += ' decompile-pill--error';
    else if (isForced) cls += ' decompile-pill--selected';
    else if (isBest) cls += ' decompile-pill--best';
    pill.className = cls;
    const label = document.createElement('span');
    label.className = 'decompile-pill-label';
    label.textContent = formatDecompilerPillLabel(name);
    pill.appendChild(label);
    appendDecompilerPillStatus(pill, info);
    pill.title = info.status === 'error'
      ? (info.errorReason || name + ' a échoué')
      : isForced
        ? name + ' (sélectionné)'
        : isBest
          ? name + ' (meilleur résultat auto)'
          : 'Utiliser ' + name;
    if (info.status !== 'error' && info.status !== 'running') {
      pill.addEventListener('click', () => {
        decompileUiState.forcedDecompiler = name;
        if (decompileUiState.payloads[name]) {
          const c = document.getElementById('decompileContent');
          if (c) renderDecompilePayload(c, decompileUiState.payloads[name]);
        }
        _refreshDecompilePills();
      });
    } else {
      pill.setAttribute('aria-disabled', 'true');
      pill.tabIndex = -1;
    }
    container.appendChild(pill);
  }
}

function _refreshDecompilePills() {
  const container = document.getElementById('decompilePills');
  if (!container) return;
  renderDecompilePills(
    container,
    decompileUiState.pillStatuses,
    decompileUiState.bestDecompiler,
    decompileUiState.forcedDecompiler,
  );
}

function getDecompileSelectionContext() {
  const sel = document.getElementById('decompileAddrSelect');
  const selectedAddr = String(sel?.value || '').trim();
  const fallbackAddr = decompileUiState.selectionMode === 'context'
    ? String(decompileUiState.selectedAddr || '').trim()
    : '';
  const resolvedAddr = selectedAddr || fallbackAddr;
  return {
    sel,
    addr: resolvedAddr,
    funcName: sel?.options[sel.selectedIndex]?.dataset?.name || findNameForAddress(resolvedAddr) || '',
  };
}

function syncDecompileSelection(addr, options = {}) {
  const sel = document.getElementById('decompileAddrSelect');
  if (!sel) return '';
  const optionAddrs = Array.from(sel.options).map((opt) => opt.value).filter(Boolean);
  const currentValue = sel.value || decompileUiState.selectedAddr || '';
  const preserveManual = options.forceContext !== true
    && decompileUiState.selectionMode === 'manual'
    && currentValue
    && optionAddrs.includes(currentValue);
  if (preserveManual) {
    if (sel.value !== currentValue) sel.value = currentValue;
    decompileUiState.selectedAddr = currentValue;
    return decompileUiState.selectedAddr;
  }
  const targetAddr = findNearestFunctionStart(addr, optionAddrs)
    || (optionAddrs.includes(decompileUiState.selectedAddr) ? decompileUiState.selectedAddr : '');
  if (targetAddr && sel.value !== targetAddr) sel.value = targetAddr;
  if (options.forceContext === true) {
    decompileUiState.selectionMode = 'context';
    _saveStorage({ decompileSelectionMode: decompileUiState.selectionMode });
  }
  decompileUiState.selectedAddr = sel.value || '';
  return decompileUiState.selectedAddr;
}

function updateDecompileHistoryControls() {
  const backBtn = document.getElementById('btnDecompileBack');
  const forwardBtn = document.getElementById('btnDecompileForward');
  const label = document.getElementById('decompileHistoryLabel');
  const { entries, index } = decompileHistoryState;
  const prev = index > 0 ? entries[index - 1] : null;
  const next = index >= 0 && index < entries.length - 1 ? entries[index + 1] : null;
  if (backBtn) {
    backBtn.disabled = !prev;
    backBtn.title = prev ? `Revenir à ${prev.label}` : 'Aucun élément précédent';
  }
  if (forwardBtn) {
    forwardBtn.disabled = !next;
    forwardBtn.title = next ? `Avancer vers ${next.label}` : 'Aucun élément suivant';
  }
  if (label) {
    const current = index >= 0 ? entries[index] : null;
    label.textContent = current ? `Courant: ${current.label}` : 'Historique vide';
  }
}

function resetDecompileHistory() {
  decompileHistoryState = {
    entries: [],
    index: -1,
  };
  updateDecompileHistoryControls();
}

function pushDecompileHistoryEntry(entry) {
  if (!entry?.binaryPath) {
    updateDecompileHistoryControls();
    return;
  }
  const current = decompileHistoryState.index >= 0
    ? decompileHistoryState.entries[decompileHistoryState.index]
    : null;
  const isSameAsCurrent = !!current
    && current.binaryPath === entry.binaryPath
    && current.decompiler === entry.decompiler
    && (current.provider || 'auto') === (entry.provider || 'auto')
    && _normalizeDecompileQuality(current.quality || 'normal') === _normalizeDecompileQuality(entry.quality || 'normal')
    && current.addr === entry.addr
    && current.full === entry.full;
  if (isSameAsCurrent) {
    current.label = entry.label;
    updateDecompileHistoryControls();
    return;
  }
  if (decompileHistoryState.index < decompileHistoryState.entries.length - 1) {
    decompileHistoryState.entries = decompileHistoryState.entries.slice(0, decompileHistoryState.index + 1);
  }
  decompileHistoryState.entries.push(entry);
  if (decompileHistoryState.entries.length > 24) {
    decompileHistoryState.entries.shift();
  }
  decompileHistoryState.index = decompileHistoryState.entries.length - 1;
  updateDecompileHistoryControls();
}

function applyDecompileHistoryStep(delta) {
  const nextIndex = decompileHistoryState.index + delta;
  const entry = decompileHistoryState.entries[nextIndex];
  if (!entry) {
    updateDecompileHistoryControls();
    return;
  }
  if (entry.binaryPath && entry.binaryPath !== getStaticBinaryPath()) {
    resetDecompileHistory();
    return;
  }
  decompileHistoryState.index = nextIndex;
  const select = document.getElementById('decompileAddrSelect');
  if (select) select.value = entry.addr || '';
  if (entry.decompiler) decompileUiState.forcedDecompiler = entry.decompiler;
  const qualitySelect = document.getElementById('decompileQualitySelect');
  if (qualitySelect && entry.quality) {
    qualitySelect.value = _normalizeDecompileQuality(entry.quality);
  }
  decompileUiState.quality = _normalizeDecompileQuality(entry.quality || 'normal');
  _saveStorage({ decompileQuality: decompileUiState.quality });
  decompileUiState.selectedAddr = entry.addr || '';
  updateDecompileHistoryControls();
  requestDecompileForCurrentSelection({ skipHistory: true });
}

function buildDecompileHistoryEntry(binaryPath, decompiler, quality, addr, funcName) {
  return {
    binaryPath,
    decompiler,
    provider: _getConfiguredDecompilerProvider(),
    quality: _normalizeDecompileQuality(quality || 'normal'),
    addr: addr || '',
    full: !addr,
    label: funcName || (addr ? addr : 'Vue globale'),
  };
}

function rerenderCurrentDecompileFromCache() {
  const container = document.getElementById('decompileContent');
  if (!container) return false;
  const bp = getStaticBinaryPath() || '';
  const quality = _normalizeDecompileQuality(document.getElementById('decompileQualitySelect')?.value || decompileUiState.quality || 'normal');
  const decompiler = _getRequestedDecompilerForQuality(quality);
  const provider = _getConfiguredDecompilerProvider();
  const { addr } = getDecompileSelectionContext();
  const full = !addr;
  if (!bp) return false;
  const cached = getCachedDecompileResult(buildDecompileRequestKey(bp, decompiler, quality, addr, full, provider, funcName));
  if (!cached) return false;
  renderDecompilePayload(container, cached);
  return true;
}

function requestDecompileForCurrentSelection(options = {}) {
  const bp = getStaticBinaryPath();
  if (!bp) return;
  const container = document.getElementById('decompileContent');
  const quality = _normalizeDecompileQuality(document.getElementById('decompileQualitySelect')?.value || decompileUiState.quality || 'normal');
  const decompiler = _getRequestedDecompilerForQuality(quality);
  const provider = _getConfiguredDecompilerProvider();
  const { addr, funcName } = getDecompileSelectionContext();
  const full = !addr;
  const requestKey = buildDecompileRequestKey(bp, decompiler, quality, addr, full, provider, funcName);
  if (!options.preserveStackEntry && !decompileUiState.pendingStackEntryName) {
    decompileUiState.activeStackEntryName = '';
    decompileUiState.pendingStackEntryName = '';
  }
  decompileUiState.quality = quality;
  _saveStorage({ decompileQuality: quality });
  decompileUiState.selectedAddr = addr || '';
  _saveStorage({ decompileAddr: decompileUiState.selectedAddr || '' });
  tabDataCache.decompile = null;
  if (!options.skipHistory) {
    pushDecompileHistoryEntry(buildDecompileHistoryEntry(bp, decompiler, quality, addr, funcName));
  }
  decompileUiState.pillStatuses = {};
  decompileUiState.bestDecompiler = '';
  decompileUiState.payloads = {};
  if (!decompiler) decompileUiState.forcedDecompiler = '';
  _refreshDecompilePills();
  const useCacheChecked = document.getElementById('useCache')?.checked !== false;
  if (options.forceRefresh || !useCacheChecked) {
    decompileResultCache.delete(requestKey);
  }
  const cached = getCachedDecompileResult(requestKey);
  if (cached && container) {
    renderDecompilePayload(container, cached);
    return;
  }
  // Deduplicate: same request already in flight, skip
  if (pendingDecompileRequests.has(requestKey)) return;
  pendingDecompileRequests.add(requestKey);
  cancelPendingDecompileHighlight();
  setStaticLoading('decompileContent', 'Décompilation en cours…');
  if (addr) {
    vscode.postMessage({ type: 'hubLoadDecompile', binaryPath: bp, addr, funcName, full: false, decompiler, quality, provider, useCache: useCacheChecked });
  } else {
    vscode.postMessage({ type: 'hubLoadDecompile', binaryPath: bp, full: true, decompiler, quality, provider, useCache: useCacheChecked });
  }
}

function _onDecompilerSourceChange() {
  const source = _getActiveDecompilerSource();
  const targetDecompiler = _getRequestedDecompilerForQuality(
    document.getElementById('decompileQualitySelect')?.value || decompileUiState.quality || 'normal'
  );
  if (targetDecompiler && _decompilerAvailability[targetDecompiler] === false) {
    vscode.postMessage({ type: 'hubInstallDecompiler', tool: targetDecompiler });
    return;
  }
  _setActiveDecompilerSource(source);
  syncDecompileSelection(window._lastDisasmAddr || decompileUiState.selectedAddr);
  requestDecompileForCurrentSelection();
}

function loadHexView(binaryPath, offset, length) {
  if (offset !== undefined) hexCurrentOffset = offset;
  if (length !== undefined) hexCurrentLength = length;
  resetHexDomState();
  window._lastHexRows = [];
  hexRenderInProgress = false;
  updateHexRenderStatus(0, 0, false);
  const container = document.getElementById('hexContent');
  if (container) {
    container.replaceChildren();
    const hint = document.createElement('p');
    hint.className = 'hint';
    hint.textContent = 'Chargement\u2026';
    container.appendChild(hint);
  }
  vscode.postMessage({
    type: 'hubLoadHexView',
    binaryPath,
    offset: hexCurrentOffset,
    length: hexCurrentLength,
  });
}

// ── Compilateur — disponibilité ────────────────────────────────
const _COMPILER_ALL_TARGETS = [
  // x86 / ARM
  { value: 'elf-x64',      label: 'ELF x86-64' },
  { value: 'elf-x86',      label: 'ELF x86' },
  { value: 'elf-arm64',    label: 'ELF ARM64' },
  { value: 'elf-arm',      label: 'ELF ARMv7' },
  // Windows
  { value: 'pe-x64',       label: 'PE x64 (Windows)' },
  { value: 'pe-x86',       label: 'PE x86 (Windows)' },
  // macOS
  { value: 'macho-arm64',  label: 'Mach-O ARM64 (macOS)' },
  { value: 'macho-x64',    label: 'Mach-O x86-64 (macOS)' },
  // MIPS
  { value: 'elf-mips',     label: 'ELF MIPS BE 32' },
  { value: 'elf-mipsel',   label: 'ELF MIPS LE 32' },
  { value: 'elf-mips64',   label: 'ELF MIPS64 BE' },
  { value: 'elf-mips64el', label: 'ELF MIPS64 LE' },
  // PowerPC
  { value: 'elf-ppc',      label: 'ELF PowerPC 32' },
  { value: 'elf-ppc64',    label: 'ELF PowerPC 64 BE' },
  { value: 'elf-ppc64le',  label: 'ELF PowerPC 64 LE' },
  // SPARC / RISC-V / s390x
  { value: 'elf-sparc64',  label: 'ELF SPARC64' },
  { value: 'elf-riscv64',  label: 'ELF RISC-V 64' },
  { value: 'elf-s390x',    label: 'ELF s390x (IBM Z)' },
  // Exotic
  { value: 'elf-m68k',     label: 'ELF M68K' },
  { value: 'elf-sh4',      label: 'ELF SuperH SH4' },
];
window._compilerData = [];
window._compilerAvMap = {};

function _buildTargetAvailability(lang, compilers) {
  const map = {};
  for (const tc of compilers) {
    if (!Array.isArray(tc.langs) || !tc.langs.includes(lang)) continue;
    for (const tgt of (tc.targets || [])) {
      if (!map[tgt] || (!map[tgt].available && tc.available)) {
        map[tgt] = {
          available: tc.available,
          available_native: tc.available_native,
          available_docker: tc.available_docker,
          native_platform_restricted: tc.native_platform_restricted || false,
          toolchain_id: tc.id,
          toolchain_label: tc.label,
        };
      }
    }
  }
  return map;
}

function _updateTargetHint(targetValue) {
  const hint = document.getElementById('compiler-target-hint');
  if (!hint) return;
  while (hint.firstChild) hint.removeChild(hint.firstChild);
  const info = window._compilerAvMap[targetValue];
  if (!info) { hint.style.display = 'none'; return; }
  if (info.available) {
    const via = info.available_native ? 'natif' : 'Docker';
    hint.style.cssText = 'display:block;margin-top:6px;padding:6px 10px;border-radius:3px;font-size:12px;line-height:1.6;background:var(--vscode-inputValidation-infoBackground,rgba(0,122,204,.12));border-left:3px solid var(--vscode-charts-blue,#007acc)';
    hint.textContent = '\u2713 ' + info.toolchain_label + ' \u2014 compilation ' + via;
    return;
  }
  hint.style.cssText = 'display:block;margin-top:6px;padding:8px 12px;border-radius:3px;font-size:12px;line-height:1.6;background:var(--vscode-inputValidation-warningBackground,rgba(255,170,0,.12));border-left:3px solid var(--vscode-charts-orange,#e8a44d)';
  const line1 = document.createElement('div');
  line1.appendChild(document.createTextNode('\u26A0 '));
  const strong = document.createElement('strong');
  strong.textContent = 'Docker requis';
  line1.appendChild(strong);
  if (info.native_platform_restricted) {
    line1.appendChild(document.createTextNode(' \u2014 sur macOS, gcc\u202F=\u202FApple Clang (ne produit pas d\u2019ELF/PE)'));
  }
  const line2 = document.createElement('div');
  line2.style.marginTop = '4px';
  line2.appendChild(document.createTextNode('Construire l\u2019image Docker : '));
  const code = document.createElement('code');
  code.style.userSelect = 'all';
  code.textContent = 'make compiler-docker-build COMPILER=' + info.toolchain_id;
  line2.appendChild(code);
  hint.appendChild(line1);
  hint.appendChild(line2);
}

function _applyCompilerAvailability(compilers) {
  const lang = document.getElementById('compilerLang')?.value || 'c';
  const targetSelect = document.getElementById('compilerTarget');
  if (!targetSelect) return;
  window._compilerAvMap = _buildTargetAvailability(lang, compilers);
  const currentVal = targetSelect.value;
  targetSelect.textContent = '';
  for (const { value, label } of _COMPILER_ALL_TARGETS) {
    const opt = document.createElement('option');
    opt.value = value;
    const info = window._compilerAvMap[value];
    if (!info) {
      opt.text = label + '  —  non disponible';
      opt.disabled = true;
    } else if (info.available) {
      const mode = info.available_native ? 'natif' : 'Docker';
      opt.text = label + '  (' + mode + ')  ✓';
    } else {
      opt.text = label + '  (Docker requis)';
    }
    targetSelect.appendChild(opt);
  }
  const hasVal = [...targetSelect.options].some(o => o.value === currentVal && !o.disabled);
  if (hasVal) {
    targetSelect.value = currentVal;
  } else {
    const first = [...targetSelect.options].find(o => !o.disabled && window._compilerAvMap[o.value]?.available);
    if (first) targetSelect.value = first.value;
  }
  _updateTargetHint(targetSelect.value);
  _buildGccCommand();
}

// ── Compilateur GCC ──────────────────────────────────────────
const COMPILER_OPTIM_HINTS = {
  '-O0': 'Aucune optimisation: garde un désassemblage proche du source.',
  '-Og': 'Debug confortable avec optimisations légères et flux plus réaliste.',
  '-O1': 'Optimisation modérée: premiers inlinings et simplifications.',
  '-O2': 'Profil équilibré: bon niveau pour observer un binaire de release courant.',
  '-O3': 'Optimisation agressive: vectorisation/inlining, code moins direct à lire.',
  '-Os': 'Optimise la taille: utile pour comparer les artefacts compacts.',
};

function _splitCompilerExtraFlags(value) {
  return String(value || '')
    .split(/\s+/)
    .map((flag) => flag.trim())
    .filter(Boolean)
    .filter((flag) => !/[\u0000\r\n]/.test(flag));
}

function _updateCompilerOptimHint() {
  const optim = document.getElementById('gccOptim')?.value || '-O0';
  const hint = document.getElementById('compilerOptimHint');
  if (hint) hint.textContent = COMPILER_OPTIM_HINTS[optim] || COMPILER_OPTIM_HINTS['-O0'];
}

function _buildCompilerFlags() {
  const target  = document.getElementById('compilerTarget')?.value || 'elf-x64';
  const isELF   = target.startsWith('elf-');
  const optim   = document.getElementById('gccOptim')?.value || '-O0';
  const debug   = document.getElementById('gccDebug')?.value || '';
  const pie     = document.getElementById('gccPie')?.value || 'no';
  const canary  = document.getElementById('gccCanary')?.value || 'off';
  const execstack = document.getElementById('gccExecstack')?.checked;
  const relro   = document.getElementById('gccRelro')?.value || 'off';
  const isStatic = document.getElementById('gccStatic')?.checked;
  const strip   = document.getElementById('gccStrip')?.checked;
  const extra   = document.getElementById('gccExtraFlags')?.value?.trim() || '';

  const f = [];
  f.push(optim);
  if (debug) f.push(debug);
  if (isELF) {
    // Linux ELF-specific protection flags
    if (canary === 'off')         f.push('-fno-stack-protector');
    else if (canary === 'basic')  f.push('-fstack-protector');
    else if (canary === 'strong') f.push('-fstack-protector-strong');
    else if (canary === 'all')    f.push('-fstack-protector-all');
    if (execstack) f.push('-z', 'execstack');
    if (pie === 'no') f.push('-fno-pie', '-no-pie');
    else              f.push('-fpie', '-pie');
    if (relro === 'partial') f.push('-Wl,-z,relro');
    else if (relro === 'full') f.push('-Wl,-z,relro,-z,now');
  }
  if (isStatic) f.push('-static');
  if (strip)    f.push('-s');
  if (extra)    f.push(..._splitCompilerExtraFlags(extra));
  return f;
}

function _buildGccCommand() {
  const src = document.getElementById('gccSourcePath')?.value?.trim() || 'source.c';
  const out = document.getElementById('gccOutputPath')?.value?.trim() || 'a.out';
  const lang = document.getElementById('compilerLang')?.value || 'c';
  const target = document.getElementById('compilerTarget')?.value || 'elf-x64';
  const isCLike = lang === 'c' || lang === 'cpp';

  const isELF = target.startsWith('elf-');
  const gccOnly = document.getElementById('compiler-gcc-only');
  if (gccOnly) gccOnly.style.display = isCLike ? '' : 'none';
  // Linux-specific protection flags only make sense for ELF targets
  const memProtSection = document.getElementById('compiler-mem-prot');
  if (memProtSection) memProtSection.style.display = (isCLike && isELF) ? '' : 'none';

  if (!isCLike) {
    const preview = document.getElementById('compilerCmdPreview');
    if (preview) preview.textContent = `${lang} build → ${target}`;
    _updateCompilerOptimHint();
    return;
  }

  const compiler = lang === 'cpp' ? 'g++' : 'gcc';
  const archFlag = target === 'elf-x86' ? ['-m32'] : target === 'elf-x64' ? ['-m64'] : [];
  const flags = _buildCompilerFlags();
  const f = [compiler, ...archFlag, ...flags, '-o', out, src];

  const preview = document.getElementById('compilerCmdPreview');
  if (preview) preview.textContent = f.join(' ');
  _updateCompilerOptimHint();
}

[
  'gccSourcePath', 'gccOutputPath', 'gccExtraFlags'
].forEach((id) => document.getElementById(id)?.addEventListener('input', _buildGccCommand));
[
  'compilerLang', 'compilerTarget', 'gccOptim', 'gccDebug', 'gccPie', 'gccCanary', 'gccRelro'
].forEach((id) => document.getElementById(id)?.addEventListener('change', _buildGccCommand));
[
  'gccExecstack', 'gccStatic', 'gccStrip'
].forEach((id) => document.getElementById(id)?.addEventListener('change', _buildGccCommand));

document.getElementById('compilerCmdPreview')?.addEventListener('click', () => {
  const txt = document.getElementById('compilerCmdPreview')?.textContent || '';
  if (txt) navigator.clipboard?.writeText(txt);
});

document.getElementById('btnBrowseCompilerSrc')?.addEventListener('click', () => {
  const lang = document.getElementById('compilerLang')?.value || 'c';
  vscode.postMessage({ type: 'compilerBrowseSource', lang });
});

document.getElementById('btnBrowseCompilerOut')?.addEventListener('click', () => {
  const target = document.getElementById('compilerTarget')?.value || 'elf-x64';
  const src = document.getElementById('gccSourcePath')?.value?.trim() || '';
  vscode.postMessage({ type: 'compilerBrowseOutput', target, src });
});

document.getElementById('compilerTarget')?.addEventListener('change', () => {
  const target = document.getElementById('compilerTarget')?.value || '';
  _updateTargetHint(target);
  _buildGccCommand();
});

document.getElementById('compilerLang')?.addEventListener('change', () => {
  _applyCompilerAvailability(window._compilerData || []);
});

document.getElementById('btnCompileGcc')?.addEventListener('click', () => {
  const src = document.getElementById('gccSourcePath')?.value?.trim() || '';
  const output = document.getElementById('gccOutputPath')?.value?.trim() || '';
  const lang = document.getElementById('compilerLang')?.value || 'c';
  const target = document.getElementById('compilerTarget')?.value || 'elf-x64';
  if (!src) { vscode.postMessage({ type: 'hubError', message: 'Source requise.' }); return; }
  const btn = document.getElementById('btnCompileGcc');
  if (btn) { btn.disabled = true; btn.classList.add('loading'); }
  const isCLike = lang === 'c' || lang === 'cpp';
  const flags = isCLike ? _buildCompilerFlags() : [];
  vscode.postMessage({ type: 'compileRequest', src, lang, target, output: output || undefined, flags });
});

_buildGccCommand();
vscode.postMessage({ type: 'compilerListRequest' });

document.getElementById('btnRefreshCompilers')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'compilerListRequest' });
});

staticBinaryInput?.addEventListener('change', () => {
  syncDynamicBinaryFieldMode();
  syncStaticWorkspaceSummary();
});

document.getElementById('btnDynamicSelectBinary')?.addEventListener('click', () => {
  setDynamicTraceStatus('Sélection du fichier de travail...');
  vscode.postMessage({ type: 'requestBinarySelection' });
});

document.getElementById('btnDynamicSelectSource')?.addEventListener('click', () => {
  setDynamicTraceStatus('Sélection du fichier C...');
  vscode.postMessage({ type: 'hubPickFile', target: 'dynamicSourcePath', fileType: 'sourceC' });
});

btnRefreshDynamicTraceHistory?.addEventListener('click', () => {
  setDynamicTraceStatus('Actualisation des traces...');
  requestDynamicTraceHistory();
});

btnClearDynamicTraceHistory?.addEventListener('click', () => {
  setDynamicTraceStatus('Nettoyage des anciennes traces...');
  vscode.postMessage({ type: 'clearDynamicTraceHistory' });
});

dynamicSourcePathInput?.addEventListener('input', () => {
  dynamicTraceInitState.sourcePath = dynamicSourcePathInput.value.trim();
  if (!dynamicTraceInitState.sourcePath) {
    dynamicTraceInitState.sourceEnrichmentEnabled = false;
    dynamicTraceInitState.sourceEnrichmentStatus = '';
    dynamicTraceInitState.sourceEnrichmentMessage = '';
  } else if (dynamicTraceInitState.sourceEnrichmentEnabled !== true) {
    dynamicTraceInitState.sourceEnrichmentStatus = 'pending';
    dynamicTraceInitState.sourceEnrichmentMessage = '';
  }
  if (dynamicSourceHint) dynamicSourceHint.textContent = buildDynamicSourceHintText(dynamicTraceInitState);
  updateArgvPayloadHint();
});

dynamicSourcePathInput?.addEventListener('blur', () => {
  requestRunTraceInit(null, binaryPathInput?.value?.trim() || '');
});


// Auto-load tab content when navigating (uses cache to avoid re-fetching)
function getStaticUseCachePreference() {
  return document.getElementById('useCache')?.checked !== false;
}

function _autoLoadTab(t) {
  const bp = getStaticBinaryPath();
  if (!bp) return;
  const useCache = getStaticUseCachePreference();
  const postStaticDebug = (event, details = {}) => {
    vscode.postMessage({ type: 'hubDebugLog', scope: 'static-autoload', event, details });
  };
  if (isRawBinarySelected() && markRawTabUnavailable(t)) {
    tabDataCache[t] = { binaryPath: bp };
    postStaticDebug('raw-unavailable', { tab: t, binaryPath: bp });
    return;
  }
  const allTabIds = Object.values(GROUPS).flat();
  const cacheHit = useCache && allTabIds.includes(t) && tabDataCache[t]?.binaryPath === bp;
  postStaticDebug('check', {
    tab: t,
    binaryPath: bp,
    cachedBinaryPath: tabDataCache[t]?.binaryPath || '',
    cacheHit,
    useCache,
  });
  if (cacheHit) return;

  if (t === 'disasm') {
    postBinaryAwareMessage('hubOpenDisasm', { binaryPath: bp, useCache, openInEditor: false });
  } else if (t === 'sections') {
    setStaticLoading('sectionsContent', 'Chargement sections…');
    postBinaryAwareMessage('hubLoadSections', { binaryPath: bp, useCache });
  } else if (t === 'info') {
    setStaticLoading('infoContent', 'Chargement infos…');
    postBinaryAwareMessage('hubLoadInfo', { binaryPath: bp, useCache });
  } else if (t === 'symbols') {
    setStaticLoading('symbolsContent', 'Chargement symboles…');
    postBinaryAwareMessage('hubLoadSymbols', { binaryPath: bp, useCache });
  } else if (t === 'strings') {
    const enc = document.getElementById('stringsEncoding')?.value || 'auto';
    const sec = document.getElementById('stringsSection')?.value || '';
    setStaticLoading('stringsContent', 'Chargement strings…');
    const minLen = parseInt(document.getElementById('stringsMinLen')?.value || '4', 10);
    postBinaryAwareMessage('hubLoadStrings', { binaryPath: bp, minLen, encoding: enc, section: sec || undefined, useCache });
  } else if (t === 'cfg') {
    setStaticLoading('cfgContent', 'Chargement CFG…');
    const cfgFuncAddr = (typeof cfgUiState !== 'undefined' ? cfgUiState.funcAddr : '')
      || (typeof decompileUiState !== 'undefined' ? decompileUiState.selectedAddr : '')
      || '';
    postStaticDebug('request-cfg', { binaryPath: bp, funcAddr: cfgFuncAddr || '', useCache });
    postBinaryAwareMessage('hubLoadCfg', { binaryPath: bp, funcAddr: cfgFuncAddr || undefined, useCache });
  } else if (t === 'callgraph') {
    setStaticLoading('callgraphContent', 'Chargement call graph…');
    postStaticDebug('request-callgraph', { binaryPath: bp, useCache });
    postBinaryAwareMessage('hubLoadCallGraph', { binaryPath: bp, useCache });
  } else if (t === 'discovered') {
    setStaticLoading('functionsContent', 'Chargement fonctions…');
    postBinaryAwareMessage(isRawBinarySelected() ? 'hubLoadDiscoveredFunctions' : 'hubLoadFunctions', { binaryPath: bp });
  } else if (callTabLoader(t, bp)) {
    // Tab loaded by registered plugin handler
  } else if (t === 'decompile') {
    setStaticLoading('decompileContent', 'Décompilation…');
    vscode.postMessage({ type: 'hubListDecompilers', provider: _getConfiguredDecompilerProvider() });
    ensureDecompileSelectionSourcesLoaded(bp);
    syncDecompileSelection(window._lastDisasmAddr || decompileUiState.selectedAddr);
    requestDecompileForCurrentSelection();
  } else if (t === 'imports') {
    setStaticLoading('importsContent', 'Analyse imports…');
    setStaticLoading('exportsContent', 'Chargement exports…');
    postBinaryAwareMessage('hubLoadImports', { binaryPath: bp });
    postBinaryAwareMessage('hubLoadExports', { binaryPath: bp });
  } else if (t === 'hex') {
    if (bp && !tabDataCache.hex) loadHexView(bp, 0, hexCurrentLength);
    if (bp && !(tabDataCache.patchList && tabDataCache.patchList.binaryPath === bp)) {
      tabDataCache.patchList = { binaryPath: bp };
      postBinaryAwareMessage('hubLoadPatches', { binaryPath: bp });
    }
  } else if (t === 'stack') {
    syncStackFrameForContext(window._lastDisasmAddr || decompileUiState.selectedAddr);
  } else if (t === 'pe_resources') {
    setStaticLoading('peResourcesContent', 'Extraction ressources PE\u2026');
    postBinaryAwareMessage('hubLoadPeResources', { binaryPath: bp });
  } else if (t === 'exceptions') {
    setStaticLoading('exceptionsContent', 'Chargement gestionnaires d\'exceptions\u2026');
    postBinaryAwareMessage('hubLoadExceptionHandlers', { binaryPath: bp });
  } else if (t === 'typed_data') {
    setStaticLoading('typedDataContent', 'Analyse des donn\u00e9es\u2026');
    vscode.postMessage(buildTypedDataRequest(bp));
  }
}

document.getElementById('cfgFuncSelect')?.addEventListener('change', function () {
  if (typeof cfgUiState !== 'undefined') cfgUiState.funcAddr = this.value;
  tabDataCache.cfg = null;
  const bp = getStaticBinaryPath();
  if (bp) postBinaryAwareMessage('hubLoadCfg', { binaryPath: bp, funcAddr: this.value || undefined, useCache: getStaticUseCachePreference() });
});
