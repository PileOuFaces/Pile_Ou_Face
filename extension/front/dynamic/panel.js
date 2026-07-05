
// Dynamic: form submit
form?.addEventListener('submit', (e) => {
  e.preventDefault();
  const binaryPath = binaryPathInput?.value?.trim() || '';
  if (!binaryPath) {
    setDynamicTraceStatus('Chemin binaire requis.');
    return;
  }

  if (runBtn) runBtn.disabled = true;
  setDynamicTraceStatus('Trace en cours...');
  vscode.postMessage({
    type: 'runTrace',
    config: {
      traceMode: 'dynamic',
      useExistingBinary: true,
      binaryPath,
      sourcePath: dynamicSourcePathInput?.value?.trim() || '',
      archBits: dynamicTraceInitState.archBits,
      pie: dynamicTraceInitState.pie,
      bufferOffset: String(dynamicTraceInitState.profile.bufferOffset ?? ''),
      bufferSize: String(dynamicTraceInitState.profile.bufferSize ?? ''),
      maxSteps: String(dynamicTraceInitState.profile.maxSteps ?? 800),
      startSymbol: String(dynamicTraceInitState.profile.startSymbol || ''),
      stopSymbol: String(dynamicTraceInitState.profile.stopSymbol || ''),
      injectPayload: !!(argvPayloadInput?.value?.trim()),
      payloadExpr: argvPayloadInput?.value?.trim() || '',
      payloadTargetMode: getDynamicPayloadTargetMode(),
      payloadTarget: getDynamicPayloadTargetMode(),
    }
  });
});

// Offset calculator — initialized by staticToolsWidgetsController.init() in hub.js
function updateOffsetCalc() {
  window.staticToolsWidgetsController?.updateOffsetCalc();
}

// Calculette: Enter, copier résultat
document.getElementById('offsetBase')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') e.preventDefault(); });
document.getElementById('offsetDelta')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') e.preventDefault(); });
document.getElementById('offsetResult')?.addEventListener('click', () => {
  const v = document.getElementById('offsetResult')?.value;
  if (v && navigator.clipboard) navigator.clipboard.writeText(v).then(() => { /* ok */ });
});
document.getElementById('offsetResult')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') e.preventDefault(); });

// Payload conversion
function doPayloadConvert() {
  const input = document.getElementById('payloadInput')?.value?.trim();
  if (!input) {
    vscode.postMessage({ type: 'hubError', message: 'Saisissez une expression.' });
    return;
  }
  vscode.postMessage({ type: 'hubPayloadToHex', payload: input });
}
document.getElementById('btnPayloadToHex')?.addEventListener('click', doPayloadConvert);
document.getElementById('payloadInput')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); doPayloadConvert(); } });

function setTraceField(name, value) {
  dynamicPresetController?.setTraceField(name, value);
}

function applyDynamicPreset(config) {
  dynamicPresetController?.applyDynamicPreset(config);
}

function parseFlexibleInt(input) {
  const raw = String(input ?? '').trim();
  if (!raw) return null;
  if (/^[+-]?\d+$/.test(raw)) return parseInt(raw, 10);
  if (/^[+-]?0x[0-9a-f]+$/i.test(raw)) {
    const sign = raw.startsWith('-') ? -1 : 1;
    const normalized = raw.replace(/^[+-]/, '');
    return sign * parseInt(normalized, 16);
  }
  return null;
}

function parseFlexibleBigInt(input) {
  const raw = String(input ?? '').trim();
  if (!raw) return null;
  try {
    if (/^[+-]?\d+$/.test(raw)) return BigInt(raw);
    if (/^[+-]?0x[0-9a-f]+$/i.test(raw)) {
      const sign = raw.startsWith('-') ? -1n : 1n;
      const normalized = raw.replace(/^[+-]/, '').toLowerCase();
      return sign * BigInt(normalized);
    }
  } catch (_) {
    return null;
  }
  return null;
}

function normalizeNoteKey(rawKey) {
  return String(rawKey || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '_')
    .replace(/[^a-z0-9_]/g, '');
}

function parseExploitNotes(rawText) {
  const lines = String(rawText || '').split(/\r?\n|;/g);
  const parsed = {};
  const keyMap = {
    cmp: 'cmpAddr',
    cmp_addr: 'cmpAddr',
    cmpaddr: 'cmpAddr',
    cmp_address: 'cmpAddr',
    padding: 'padding',
    pad: 'padding',
    overflow: 'padding',
    buffer_size: 'bufferSize',
    buffersize: 'bufferSize',
    suffix: 'suffix',
    payload_suffix: 'suffix',
    payload: 'payloadExpr',
    payload_expr: 'payloadExpr',
    payloadexpr: 'payloadExpr',
    buffer_offset: 'bufferOffset',
    bufoffset: 'bufferOffset',
    capture_size: 'captureSize',
    capturesize: 'captureSize',
    start: 'startSymbol',
    start_symbol: 'startSymbol',
    target: 'targetSymbol',
    target_symbol: 'targetSymbol',
    stop: 'targetSymbol',
    stop_symbol: 'targetSymbol',
    max_steps: 'maxSteps',
    maxstep: 'maxSteps',
    steps: 'maxSteps',
    payload_target: 'payloadTarget',
    cmp_value: 'cmpValue',
    cmp_immediate: 'cmpValue',
    immediate: 'cmpValue',
    cmp_width: 'cmpWidth',
    width: 'cmpWidth'
  };

  for (const lineRaw of lines) {
    const line = lineRaw.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    const sepIdx = line.search(/[:=]/);
    if (sepIdx <= 0) continue;
    const key = normalizeNoteKey(line.slice(0, sepIdx));
    const value = line.slice(sepIdx + 1).trim();
    if (!value) continue;
    const canonical = keyMap[key];
    if (!canonical) continue;
    parsed[canonical] = value;
  }

  if (parsed.cmpAddr && /^(?:0x)?[0-9a-f]+$/i.test(parsed.cmpAddr)) {
    parsed.cmpAddr = parsed.cmpAddr.startsWith('0x') ? parsed.cmpAddr : `0x${parsed.cmpAddr}`;
  }
  parsed.padding = parseFlexibleInt(parsed.padding);
  parsed.bufferSize = parseFlexibleInt(parsed.bufferSize);
  parsed.bufferOffset = parseFlexibleInt(parsed.bufferOffset);
  parsed.captureSize = parseFlexibleInt(parsed.captureSize);
  parsed.maxSteps = parseFlexibleInt(parsed.maxSteps);
  parsed.cmpWidth = parseFlexibleInt(parsed.cmpWidth);
  parsed.cmpValue = parseFlexibleBigInt(parsed.cmpValue);
  return parsed;
}

function deriveSuffixFromCmpValue(cmpValue, cmpWidthHint) {
  if (cmpValue === null || cmpValue === undefined) return null;
  let width = cmpWidthHint;
  if (![1, 2, 4, 8].includes(width)) {
    if (cmpValue < 0n) width = 4;
    else if (cmpValue <= 0xffn) width = 1;
    else if (cmpValue <= 0xffffn) width = 2;
    else if (cmpValue <= 0xffffffffn) width = 4;
    else width = 8;
  }
  let masked = BigInt.asUintN(width * 8, cmpValue);
  const bytes = [];
  for (let i = 0; i < width; i += 1) {
    bytes.push(Number(masked & 0xffn));
    masked >>= 8n;
  }
  const printable = bytes.every((b) => b >= 0x20 && b <= 0x7e && b !== 0x2b && b !== 0x2a);
  return printable ? String.fromCharCode(...bytes) : 'B'.repeat(Math.max(4, width));
}

document.getElementById('btnPrepareDynamic')?.addEventListener('click', () => {
  const startSymbol = document.getElementById('exploitStartSymbol')?.value?.trim() || 'main';
  const targetSymbol = document.getElementById('exploitTargetSymbol')?.value?.trim() || 'win';
  const payloadSuffix = document.getElementById('exploitPayloadSuffix')?.value?.trim() || 'CCCC';
  const payloadTarget = document.getElementById('exploitPayloadTarget')?.value || 'argv1';
  const maxSteps = document.getElementById('exploitMaxSteps')?.value?.trim() || '400';
  const bufferSizeRaw = document.getElementById('exploitBufferSize')?.value?.trim() || '64';
  const bufferSize = parseInt(bufferSizeRaw, 10);
  if (!Number.isFinite(bufferSize) || bufferSize <= 0) {
    vscode.postMessage({ type: 'hubError', message: 'Taille buffer invalide.' });
    return;
  }

  const is32Bit = Number(dynamicTraceInitState.archBits) === 32;
  const suggestedOffset = is32Bit
    ? -Math.max(bufferSize + 16, 64)
    : -Math.max(bufferSize + 32, 96);
  const suggestedCaptureSize = is32Bit
    ? Math.max(bufferSize + 48, 96)
    : Math.max(bufferSize + 64, 128);
  const payloadExpr = `A*${bufferSize}+${payloadSuffix}`;
  applyDynamicPreset({
    startSymbol,
    targetSymbol,
    payloadExpr,
    payloadTarget,
    maxSteps,
    suggestedOffset,
    suggestedCaptureSize,
    binaryPath: getStaticBinaryPath()
  });
});

document.getElementById('btnAutoFromCmp')?.addEventListener('click', () => {
  const cmpAddr = document.getElementById('exploitCmpAddr')?.value?.trim();
  const bp = getStaticBinaryPath();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Sélectionnez un binaire.' });
    return;
  }
  if (!cmpAddr) {
    vscode.postMessage({ type: 'hubError', message: 'Indiquez une adresse CMP.' });
    return;
  }
  const hint = document.getElementById('exploitAutoHint');
  if (hint) hint.textContent = 'Analyse du CMP en cours…';
  vscode.postMessage({ type: 'hubAutoFromCmp', binaryPath: bp, cmpAddr });
});

function runAutoFromNotes() {
  const notesText = document.getElementById('exploitNotes')?.value || '';
  const hint = document.getElementById('exploitAutoHint');
  if (!notesText.trim()) {
    vscode.postMessage({ type: 'hubError', message: 'Ajoutez des notes (format key=value).' });
    return false;
  }

  const notes = parseExploitNotes(notesText);
  const bp = getStaticBinaryPath();

  if (notes.cmpAddr) {
    const cmpInput = document.getElementById('exploitCmpAddr');
    if (cmpInput) cmpInput.value = notes.cmpAddr;
  }
  if (notes.startSymbol) {
    const el = document.getElementById('exploitStartSymbol');
    if (el) el.value = notes.startSymbol;
  }
  if (notes.targetSymbol) {
    const el = document.getElementById('exploitTargetSymbol');
    if (el) el.value = notes.targetSymbol;
  }
  if (Number.isFinite(notes.maxSteps) && notes.maxSteps > 0) {
    const el = document.getElementById('exploitMaxSteps');
    if (el) el.value = String(notes.maxSteps);
  }
  if (Number.isFinite(notes.bufferSize) && notes.bufferSize > 0) {
    const el = document.getElementById('exploitBufferSize');
    if (el) el.value = String(notes.bufferSize);
  }
  if (notes.payloadTarget) {
    const targetSel = document.getElementById('exploitPayloadTarget');
    if (targetSel && Array.from(targetSel.options).some((o) => o.value === notes.payloadTarget)) {
      targetSel.value = notes.payloadTarget;
    }
  }

  let payloadExpr = String(notes.payloadExpr || '').trim();
  if (!payloadExpr && Number.isFinite(notes.padding) && notes.padding > 0) {
    let suffix = String(notes.suffix || '').trim();
    if (!suffix) suffix = deriveSuffixFromCmpValue(notes.cmpValue, notes.cmpWidth) || '';
    if (!suffix) suffix = 'CCCC';
    payloadExpr = `A*${notes.padding}+${suffix}`;
    const suffixInput = document.getElementById('exploitPayloadSuffix');
    if (suffixInput) suffixInput.value = suffix;
    const sizeInput = document.getElementById('exploitBufferSize');
    if (sizeInput) sizeInput.value = String(notes.padding);
  }

  if (payloadExpr) {
    const startSymbol = document.getElementById('exploitStartSymbol')?.value?.trim() || 'main';
    const targetSymbol = document.getElementById('exploitTargetSymbol')?.value?.trim() || 'win';
    const payloadTarget = document.getElementById('exploitPayloadTarget')?.value || 'argv1';
    const maxSteps = document.getElementById('exploitMaxSteps')?.value?.trim() || '400';
    const is32Bit = Number(dynamicTraceInitState.archBits) === 32;
    const padding = Number.isFinite(notes.padding) && notes.padding > 0
      ? notes.padding
      : parseFlexibleInt(document.getElementById('exploitBufferSize')?.value || '64') || 64;
    const suggestedOffset = Number.isFinite(notes.bufferOffset)
      ? notes.bufferOffset
      : (is32Bit ? -Math.max(padding + 16, 64) : -Math.max(padding + 32, 96));
    const suggestedCaptureSize = Number.isFinite(notes.captureSize)
      ? notes.captureSize
      : (is32Bit ? Math.max(padding + 48, 96) : Math.max(padding + 64, 128));

    applyDynamicPreset({
      startSymbol,
      targetSymbol,
      payloadExpr,
      payloadTarget,
      maxSteps,
      suggestedOffset,
      suggestedCaptureSize,
      binaryPath: bp
    });
    if (hint) hint.textContent = `Auto Notes OK: ${payloadExpr} (offset=${suggestedOffset}, capture=${suggestedCaptureSize})`;
    return true;
  }

  if (notes.cmpAddr) {
    if (!bp) {
      vscode.postMessage({ type: 'hubError', message: 'Sélectionnez un binaire pour utiliser cmp=...' });
      return false;
    }
    if (hint) hint.textContent = 'Analyse du CMP (depuis notes) en cours…';
    vscode.postMessage({ type: 'hubAutoFromCmp', binaryPath: bp, cmpAddr: notes.cmpAddr });
    return true;
  }

  vscode.postMessage({
    type: 'hubError',
    message: 'Notes insuffisantes: utilisez payload=..., ou padding=... (+ suffix=.../cmp_value=...), ou cmp=...'
  });
  return false;
}

document.getElementById('btnAutoFromNotes')?.addEventListener('click', runAutoFromNotes);
document.getElementById('btnAutoFromNotesWidget')?.addEventListener('click', runAutoFromNotes);

// Payload result: copier au clic
document.getElementById('payloadHexResult')?.addEventListener('click', function () {
  const v = this.textContent;
  if (v && v !== '—' && !v.startsWith('Error') && navigator.clipboard) {
    navigator.clipboard.writeText(v);
    this.classList.add('copied');
    setTimeout(() => this.classList.remove('copied'), 600);
  }
});

document.getElementById('btnGoToAddr')?.addEventListener('click', () => {
  const val = document.getElementById('goToAddrInput')?.value?.trim();
  if (!val) return;
  const bp = getStaticBinaryPath();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Sélectionnez un binaire.' });
    return;
  }
  const looksLikeAddr = /^(0x)?[0-9a-fA-F]+$/.test(val);
  if (looksLikeAddr) {
    const norm = val.startsWith('0x') ? val : '0x' + val;
    window._lastDisasmAddr = norm;
    updateActiveContextBars(norm);
    if (typeof navPush === 'function') navPush(norm, { tab: 'disasm', spanLength: 1, source: 'Go to' });
    vscode.postMessage({ type: 'hubGoToAddress', addr: norm, binaryPath: bp });
  } else {
    vscode.postMessage({ type: 'hubGoToEntryPoint', binaryPath: bp, symbol: val });
  }
});

document.getElementById('btnAddAnnotation')?.addEventListener('click', () => {
  const badge = document.getElementById('annotationAddrBadge');
  const addr = badge?.dataset.addr || '';
  const comment = document.getElementById('annotationComment')?.value?.trim();
  const name = (document.getElementById('annotationName')?.value || '').trim();
  const bp = getStaticBinaryPath();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Sélectionnez un binaire.' });
    return;
  }
  if (!addr) {
    vscode.postMessage({ type: 'hubError', message: 'Cliquez d\'abord une ligne dans le désassemblage.' });
    return;
  }
  vscode.postMessage({ type: 'hubSaveAnnotation', binaryPath: bp, addr, comment, name });
});

document.getElementById('btnXrefs')?.addEventListener('click', () => {
  const inputAddr = document.getElementById('goToAddrInput')?.value?.trim();
  const selectedAddr = document.getElementById('annotationAddrBadge')?.dataset.addr || '';
  const addr = inputAddr || selectedAddr || window._lastDisasmAddr || '';
  if (!addr) {
    vscode.postMessage({ type: 'hubError', message: 'Indiquez une adresse ou cliquez une ligne du désassemblage.' });
    return;
  }
  const el = document.getElementById('xrefsResult');
  const contentEl = document.getElementById('xrefsResultContent');
  if (el) {
    el.style.display = 'block';
    (contentEl || el).innerHTML = '<p class="xrefs-msg loading">Analyse des références croisées…</p>';
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
  const bp = getStaticBinaryPath();
  const norm = addr.startsWith('0x') ? addr : '0x' + addr;
  const input = document.getElementById('goToAddrInput');
  if (input) input.value = norm;
  const mode = document.getElementById('xrefsMode')?.value || 'to';
  vscode.postMessage({ type: 'hubLoadXrefs', addr: norm, binaryPath: bp || '', mode });
});

document.getElementById('btnExportDisasm')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'hubExportDisasm', binaryPath: getStaticBinaryPath() });
});

function doExportData(dataType, format) {
  let data, suggestedName;
  if (dataType === 'symbols') {
    data = window.symbolsCache || [];
    suggestedName = `symbols_export.${format}`;
  } else if (dataType === 'strings') {
    data = stringsCache || [];
    suggestedName = `strings_export.${format}`;
  } else if (dataType === 'xrefs') {
    data = window.xrefsCache || { refs: [], targets: [], addr: '', mode: '' };
    suggestedName = `xrefs_${(data.addr || 'export').replace(/^0x/, '')}.${format}`;
  } else return;
  if ((Array.isArray(data) && data.length === 0) || (!Array.isArray(data) && !data.refs?.length && !data.targets?.length)) {
    vscode.postMessage({ type: 'hubError', message: 'Aucune donnée à exporter.' });
    return;
  }
  vscode.postMessage({ type: 'hubExportData', dataType, format, data, suggestedName });
}
document.getElementById('btnExportSymbolsJson')?.addEventListener('click', () => doExportData('symbols', 'json'));
document.getElementById('btnExportSymbolsCsv')?.addEventListener('click', () => doExportData('symbols', 'csv'));
document.getElementById('btnExportStringsJson')?.addEventListener('click', () => doExportData('strings', 'json'));
document.getElementById('btnExportStringsCsv')?.addEventListener('click', () => doExportData('strings', 'csv'));
document.getElementById('btnExportXrefsJson')?.addEventListener('click', () => doExportData('xrefs', 'json'));
document.getElementById('btnExportXrefsCsv')?.addEventListener('click', () => doExportData('xrefs', 'csv'));

document.getElementById('btnExportCfgSvg')?.addEventListener('click', () => {
  const svgEl = document.querySelector('#cfgContent .cfg-svg');
  if (!svgEl) {
    vscode.postMessage({ type: 'hubError', message: 'Ouvrez d\'abord le graphe CFG.' });
    return;
  }
  const svg = svgEl.outerHTML;
  vscode.postMessage({ type: 'hubExportCfgSvg', svg });
});

document.getElementById('btnExportCgSvg')?.addEventListener('click', () => {
  const svgEl = document.querySelector('#callgraphContent .cfg-svg');
  if (!svgEl) {
    vscode.postMessage({ type: 'hubError', message: 'Ouvrez d\'abord le call graph.' });
    return;
  }
  const svg = svgEl.outerHTML;
  vscode.postMessage({ type: 'hubExportCgSvg', svg });
});

document.getElementById('btnHexGo')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  if (!bp) return;
  const raw = document.getElementById('hexOffsetInput')?.value?.trim() || '0';
  const offset = parseInt(raw, raw.startsWith('0x') ? 16 : 10) || 0;
  const length = parseInt(document.getElementById('hexLengthSelect')?.value || '512', 10);
  tabDataCache.hex = null;
  loadHexView(bp, offset, length);
});
document.getElementById('btnHexPrev')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath(); if (!bp) return;
  tabDataCache.hex = null;
  loadHexView(bp, Math.max(0, hexCurrentOffset - hexCurrentLength), hexCurrentLength);
});
document.getElementById('btnHexNext')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath(); if (!bp) return;
  tabDataCache.hex = null;
  loadHexView(bp, hexCurrentOffset + hexCurrentLength, hexCurrentLength);
});
document.getElementById('btnHexToggleMeta')?.addEventListener('click', () => {
  hexUiState.compact = !hexUiState.compact;
  _saveStorage({ hexCompact: hexUiState.compact });
  applyHexLayoutMode();
});
document.getElementById('btnHexOpenSelection')?.addEventListener('click', () => {
  openHexSelectionInDisasm();
});
document.getElementById('btnHexResetSelection')?.addEventListener('click', () => {
  collapseHexSelectionToActive();
});
document.getElementById('btnHexPatch')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath(); if (!bp) return;
  const raw = document.getElementById('hexPatchOffset')?.value?.trim() || '0';
  const offset = parseInt(raw, raw.startsWith('0x') ? 16 : 10);
  if (isNaN(offset)) {
    const status = document.getElementById('hexPatchStatus');
    if (status) { status.className = 'hex-patch-status error'; status.textContent = 'Offset invalide'; }
    return;
  }
  const bytesHex = document.getElementById('hexPatchBytes')?.value?.trim() || '';
  if (!bytesHex) return;
  vscode.postMessage({ type: 'hubPatchBytes', binaryPath: bp, offset, bytesHex });
});
document.getElementById('btnHexUndo')?.addEventListener('click', () => {
  if (!hexPatchHistory.length) return;
  const bp = getStaticBinaryPath(); if (!bp) return;
  const last = hexPatchHistory[hexPatchHistory.length - 1];
  if (!last?.id) return;
  vscode.postMessage({ type: 'hubRevertPatch', binaryPath: bp, patchId: last.id });
});
document.getElementById('btnHexRedo')?.addEventListener('click', () => {
  if (!hexPatchRedoHistory.length) return;
  const bp = getStaticBinaryPath(); if (!bp) return;
  const entry = hexPatchRedoHistory[hexPatchRedoHistory.length - 1];
  if (!entry?.id) return;
  vscode.postMessage({ type: 'hubRedoPatch', binaryPath: bp, patchId: entry.id });
});
document.getElementById('hexContent')?.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    openHexSelectionInDisasm();
  } else if (event.key === 'Escape') {
    event.preventDefault();
    collapseHexSelectionToActive();
  }
});
document.getElementById('btnRevertAll')?.addEventListener('click', function() {
  const bp = getStaticBinaryPath();
  if (bp) vscode.postMessage({ type: 'hubRevertAllPatches', binaryPath: bp });
});
applyHexLayoutMode();
updateHexSelectionButtons();

document.getElementById('btnYaraBrowse')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'requestRulesSelection', target: 'manual' });
});
document.querySelectorAll('input[name="yaraRulesMode"]').forEach((input) => {
  input.addEventListener('change', () => {
    if (!input.checked) return;
    setSelectedYaraMode(input.value);
  });
});
document.getElementById('yaraRulesPath')?.addEventListener('input', () => {
  _saveStorage({ yaraRulesPath: document.getElementById('yaraRulesPath')?.value || '' });
  applyYaraModeUi();
});
document.getElementById('btnYaraScan')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  if (!bp) { vscode.postMessage({ type: 'hubError', message: 'Indiquez un binaire.' }); return; }
  const rules = document.getElementById('yaraRulesPath')?.value?.trim() || '';
  if (!rules) { vscode.postMessage({ type: 'hubError', message: 'Choisissez un fichier .yar ou un dossier de règles.' }); return; }
  vscode.postMessage({ type: 'hubPluginInvoke', feature: 'yara_scan', binaryPath: bp, payload: { rulesPath: rules, rulesMode: getSelectedYaraMode() } });
});
document.getElementById('btnCapaScan')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  if (!bp) { vscode.postMessage({ type: 'hubError', message: 'Indiquez un binaire.' }); return; }
  vscode.postMessage({ type: 'hubPluginInvoke', feature: 'capa_scan', binaryPath: bp, payload: {} });
});

document.getElementById('capaFilterInput')?.addEventListener('input', renderCapaResults);
document.getElementById('capaNamespaceFilter')?.addEventListener('change', renderCapaResults);
document.getElementById('yaraFilterInput')?.addEventListener('input', renderYaraResults);
document.getElementById('btnCapaExportJson')?.addEventListener('click', () => {
  downloadDetectionJson('capa-results.json', {
    binaryPath: getStaticBinaryPath(),
    capabilities: detectionUiState.capaCapabilities,
    error: detectionUiState.capaError || null,
  });
});
document.getElementById('btnYaraExportJson')?.addEventListener('click', () => {
  downloadDetectionJson('yara-results.json', {
    binaryPath: getStaticBinaryPath(),
    rulesMode: getSelectedYaraMode(),
    rulesPath: document.getElementById('yaraRulesPath')?.value?.trim() || '',
    matches: detectionUiState.yaraMatches,
    error: detectionUiState.yaraError || null,
  });
});
setSelectedYaraMode(detectionUiState.yaraMode, { skipSave: true });
const initialYaraPathInput = document.getElementById('yaraRulesPath');
if (initialYaraPathInput && _loadStorage().yaraRulesPath) {
  initialYaraPathInput.value = String(_loadStorage().yaraRulesPath || '');
}
applyYaraModeUi();

// Décompilateur : auto-décompile quand on change de fonction
document.getElementById('decompileAddrSelect')?.addEventListener('change', () => {
  decompileUiState.selectionMode = 'manual';
  _saveStorage({ decompileSelectionMode: decompileUiState.selectionMode });
  const { addr } = getDecompileSelectionContext();
  if (addr) setActiveAddressContext(addr, 1, { preserveHexSelection: true });
  requestDecompileForCurrentSelection();
  const bp = getStaticBinaryPath();
  if (bp && addr) {
    const cached = getCachedStackFrame(bp, addr);
    if (cached) renderStackFrame(cached);
    else ensureStackFrameLoaded(bp, addr);
  } else {
    decompileUiState.selectedAddr = '';
    _saveStorage({ decompileAddr: '' });
  }
});
document.getElementById('btnDecompileBack')?.addEventListener('click', () => {
  applyDecompileHistoryStep(-1);
});
document.getElementById('btnDecompileForward')?.addEventListener('click', () => {
  applyDecompileHistoryStep(1);
});
document.getElementById('decompileSearchInput')?.addEventListener('input', (event) => {
  decompileUiState.searchQuery = String(event.target?.value || '');
  decompileUiState.activeSearchHit = decompileUiState.searchQuery.trim() ? 0 : -1;
  _saveStorage({ decompileSearch: decompileUiState.searchQuery });
  const pre = document.querySelector('#decompileContent pre');
  clearDecompileSearchHighlights(pre);
  if (decompileUiState.searchQuery.trim()) {
    decorateDecompileSearch(pre, decompileUiState.searchQuery);
  } else {
    updateDecompileSearchUi(0);
  }
});
document.getElementById('decompileSearchInput')?.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    event.preventDefault();
    if (!decompileUiState.searchQuery) return;
    decompileUiState.searchQuery = '';
    decompileUiState.activeSearchHit = -1;
    _saveStorage({ decompileSearch: '' });
    clearDecompileSearchHighlights(document.querySelector('#decompileContent pre'));
    updateDecompileSearchUi(0);
    return;
  }
  if (event.key !== 'Enter') return;
  event.preventDefault();
  stepDecompileSearchHit(event.shiftKey ? -1 : 1);
});
document.getElementById('btnDecompileSearchPrev')?.addEventListener('click', () => {
  stepDecompileSearchHit(-1);
});
document.getElementById('btnDecompileSearchNext')?.addEventListener('click', () => {
  stepDecompileSearchHit(1);
});
updateDecompileHistoryControls();
updateDecompileSearchUi();

// Rules Manager — formulaire d'ajout
['btnAddYaraRule', 'btnAddYaraGlobalRule', 'btnAddCapaRule', 'btnAddCapaGlobalRule'].forEach(function(btnId) {
  var btn = document.getElementById(btnId);
  if (!btn) return;
  btn.addEventListener('click', function() {
    var ruleType = btn.dataset.ruletype;
    var ruleScope = btn.dataset.rulescope || 'project';
    document.getElementById('rulesEditId').value = '';
    document.getElementById('rulesAddType').value = ruleType;
    document.getElementById('rulesAddScope').value = ruleScope;
    document.getElementById('rulesAddFormTitle').textContent =
      'Ajouter une règle ' + ruleType.toUpperCase() + (ruleScope === 'global' ? ' globale' : ' projet');
    document.getElementById('rulesAddName').value = '';
    document.getElementById('rulesAddContent').value = '';
    document.getElementById('rulesAddName').placeholder =
      ruleType === 'yara' ? 'ma_regle.yar' : 'ma_regle.yml';
    document.getElementById('rulesAddForm').style.display = '';
  });
});

var btnRulesAddCancel = document.getElementById('btnRulesAddCancel');
if (btnRulesAddCancel) {
  btnRulesAddCancel.addEventListener('click', function() {
    document.getElementById('rulesAddForm').style.display = 'none';
    document.getElementById('rulesEditId').value = '';
  });
}

var btnRulesAddSave = document.getElementById('btnRulesAddSave');
if (btnRulesAddSave) {
  btnRulesAddSave.addEventListener('click', function() {
    var editId = document.getElementById('rulesEditId').value || '';
    var name = (document.getElementById('rulesAddName').value || '').trim();
    var content = document.getElementById('rulesAddContent').value || '';
    var ruleType = document.getElementById('rulesAddType').value;
    var scope = document.getElementById('rulesAddScope').value || 'project';
    if (!name) { alert('Veuillez saisir un nom de fichier.'); return; }
    if (editId) {
      vscode.postMessage({ type: 'hubUpdateUserRule', ruleId: editId, name: name, content: content });
    } else {
      vscode.postMessage({ type: 'hubAddUserRule', name: name, ruleType: ruleType, content: content, scope: scope });
    }
    document.getElementById('rulesAddForm').style.display = 'none';
    document.getElementById('rulesEditId').value = '';
  });
}



function initDynamicListeners() {
binaryPathInput?.addEventListener('input', () => {
  if (staticBinaryInput) staticBinaryInput.value = binaryPathInput.value;
});
}
