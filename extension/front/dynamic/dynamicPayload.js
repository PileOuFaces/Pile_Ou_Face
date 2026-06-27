/**
 * @file dynamicPayload.js
 * @brief Dynamic payload building, exploit helper, pwntools integration,
 *        payload preview, and related utilities for the hub webview.
 */

// DOM element references (not already declared in shared/state.js)
const payloadBuilderInput = document.getElementById('payloadBuilderInput');
const payloadFileSource = document.getElementById('payloadFileSource');
const payloadFileGuestPath = document.getElementById('payloadFileGuestPath');
const payloadFileHostPath = document.getElementById('payloadFileHostPath');
const payloadFileContent = document.getElementById('payloadFileContent');
const exploitHelperTemplate = document.getElementById('exploitHelperTemplate');
const exploitHelperArch = document.getElementById('exploitHelperArch');
const exploitHelperEndian = document.getElementById('exploitHelperEndian');
const exploitHelperBadchars = document.getElementById('exploitHelperBadchars');
const btnDynamicImportPwntoolsScript = document.getElementById('btnDynamicImportPwntoolsScript');
const btnAnalyzePwntoolsScript = document.getElementById('btnAnalyzePwntoolsScript');
const payloadPwntoolsSourceLabel = document.getElementById('payloadPwntoolsSourceLabel');
const payloadPwntoolsScriptInput = document.getElementById('payloadPwntoolsScriptInput');
const payloadPwntoolsScriptWarning = document.getElementById('payloadPwntoolsScriptWarning');
const payloadPwntoolsCaptureList = document.getElementById('payloadPwntoolsCaptureList');
const payloadPreviewStatus = document.getElementById('payloadPreviewStatus');
const payloadPreviewTarget = document.getElementById('payloadPreviewTarget');
const payloadPreviewSize = document.getElementById('payloadPreviewSize');
const payloadPreviewHex = document.getElementById('payloadPreviewHex');
const payloadPreviewAscii = document.getElementById('payloadPreviewAscii');
const payloadPreviewTruncated = document.getElementById('payloadPreviewTruncated');
const payloadPreviewSnippetDetails = document.getElementById('payloadPreviewSnippetDetails');
const payloadPwntoolsSnippet = document.getElementById('payloadPwntoolsSnippet');
const payloadPreviewWarnings = document.getElementById('payloadPreviewWarnings');
const dynamicPreviewCard = document.querySelector('#panel-dynamic .dynamic-preview-card');
const dynamicPreviewCardHeader = document.getElementById('payloadPreviewCardHeader');
const dynamicPreviewCardBody = document.getElementById('payloadPreviewCardBody');
const dynamicPreviewToggleLabel = document.getElementById('payloadPreviewToggleLabel');
const POF_PREVIEW_OPEN_KEY = 'pof-preview-open';

let dynamicPayloadPreviewState = null;

function truncateDebugValue(value, limit = 160) {
  const text = String(value ?? '');
  return text.length > limit ? `${text.slice(0, limit)}...` : text;
}

function sanitizeDebugDetails(details = {}) {
  const out = {};
  Object.entries(details && typeof details === 'object' ? details : {}).forEach(([key, value]) => {
    if (Array.isArray(value)) {
      out[key] = value.slice(0, 12).map((item) => (
        item && typeof item === 'object' ? sanitizeDebugDetails(item) : truncateDebugValue(item)
      ));
    } else if (value && typeof value === 'object') {
      out[key] = sanitizeDebugDetails(value);
    } else {
      out[key] = truncateDebugValue(value);
    }
  });
  return out;
}

function debugDynamicPayload(event, details = {}) {
  const payload = sanitizeDebugDetails(details);
  try {
    console.debug(`[pof:payload] ${event}`, payload);
  } catch (_) {
    // ignore console failures in restricted webviews
  }
  try {
    vscode.postMessage({
      type: 'hubDebugLog',
      scope: 'payload',
      event,
      details: payload,
    });
  } catch (_) {
    // ignore logging failures
  }
}

function buildDynamicSourceHintText({
  sourcePath = '',
  sourceEnrichmentEnabled = false,
  sourceEnrichmentStatus = '',
  sourceEnrichmentMessage = ''
} = {}) {
  return hubPayloadCore.buildSourceHintText({
    sourcePath,
    sourceEnrichmentEnabled,
    sourceEnrichmentStatus,
    sourceEnrichmentMessage
  });
}

function normalizeDynamicPayloadTargetMode(value) {
  return hubPayloadCore.normalizePayloadTargetMode(value);
}

function normalizeDynamicEffectiveTarget(value) {
  return hubPayloadCore.normalizeEffectiveTarget(value);
}

// Short aliases injected into payloadStateController as dep names.
function normalizePayloadTargetMode(value) {
  return normalizeDynamicPayloadTargetMode(value);
}

function normalizeEffectiveTarget(value) {
  return normalizeDynamicEffectiveTarget(value);
}

function dynamicPayloadTargetLabel(target) {
  return hubPayloadCore.payloadTargetLabel(target);
}

function getDynamicPayloadTargetMode() {
  if (payloadStateController?.getPayloadTargetMode) {
    return payloadStateController.getPayloadTargetMode();
  }
  return normalizeDynamicPayloadTargetMode(
    dynamicPayloadTargetMode?.value || dynamicTraceInitState.payloadTargetMode || 'auto'
  );
}

function getDynamicEffectivePayloadTarget() {
  if (payloadStateController?.getEffectivePayloadTarget) {
    return payloadStateController.getEffectivePayloadTarget();
  }
  const mode = getDynamicPayloadTargetMode();
  if (mode !== 'auto') return normalizeDynamicEffectiveTarget(mode);
  return normalizeDynamicEffectiveTarget(dynamicTraceInitState.payloadTargetAuto || dynamicTraceInitState.payloadTargetEffective);
}

function buildDynamicPayloadTargetHint() {
  if (payloadStateController?.getPayloadTargetHint) {
    return payloadStateController.getPayloadTargetHint();
  }
  const mode = getDynamicPayloadTargetMode();
  if (mode !== 'auto') return `${dynamicPayloadTargetLabel(mode)} force manuellement.`;
  return String(dynamicTraceInitState.payloadTargetReason || 'Auto: aucune source claire, fallback sur argv[1]');
}

function getDynamicTraceInitState() {
  return dynamicTraceInitState;
}

function setDynamicTraceInitState(nextState) {
  dynamicTraceInitState = nextState || dynamicTraceInitState;
  return dynamicTraceInitState;
}

function getDynamicTraceHistoryState() {
  return dynamicTraceHistoryState;
}

function setDynamicTraceHistoryState(nextState) {
  dynamicTraceHistoryState = nextState || dynamicTraceHistoryState;
  return dynamicTraceHistoryState;
}

function getDynamicPayloadPreviewState() {
  return dynamicPayloadPreviewState;
}

function setDynamicPayloadPreviewState(nextState) {
  dynamicPayloadPreviewState = nextState;
  return dynamicPayloadPreviewState;
}

function requestRunTraceInit(preset = null, forcedBinaryPath = '') {
  if (runTraceController?.requestRunTraceInit) {
    runTraceController.requestRunTraceInit(preset, forcedBinaryPath);
    return;
  }
  vscode.postMessage({
    type: 'requestRunTraceInit',
    binaryPath: forcedBinaryPath || binaryPathInput?.value?.trim() || '',
    sourcePath: dynamicSourcePathInput?.value?.trim() || dynamicTraceInitState.sourcePath || '',
    payloadTargetMode: getDynamicPayloadTargetMode(),
    preset
  });
}

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

function getExploitHelperApi() {
  return window.PofExploitHelper || null;
}

function getPayloadPreviewApi() {
  return window.PofPayloadPreview || null;
}

function normalizeDynamicPayloadMode(mode) {
  if (payloadStateController?.normalizePayloadMode) {
    return payloadStateController.normalizePayloadMode(mode);
  }
  return hubPayloadCore.normalizePayloadMode(mode);
}

function normalizePayloadBuilderLevel(level, fallback = 'beginner') {
  return hubPayloadCore.normalizePayloadBuilderLevel(level, fallback);
}

function getDynamicPayloadMode() {
  if (payloadStateController?.getPayloadMode) {
    return payloadStateController.getPayloadMode();
  }
  return payloadTabsController?.getMode() || 'payload_builder';
}

function getDynamicPayloadBuilderLevel() {
  if (payloadBuilderController?.getBuilderLevel) {
    return payloadBuilderController.getBuilderLevel();
  }
  return payloadTabsController?.getBuilderLevel() || 'beginner';
}

function getDynamicPayloadBuilderHint(level = getDynamicPayloadBuilderLevel()) {
  if (payloadBuilderController?.getBuilderHint) {
    return payloadBuilderController.getBuilderHint(level);
  }
  if (normalizePayloadBuilderLevel(level) === 'advanced') {
    return 'Advanced : `b"A"*8`, `p32(0xdeadbeef)`, `flat([...])`, `cyclic(128)`.';
  }
  return 'Beginner : `A*8`, `AAAA`, `\\x41\\x42`.';
}

function updatePayloadBuilderUi() {
  if (payloadBuilderController?.refreshPayloadBuilderUi) {
    payloadBuilderController.refreshPayloadBuilderUi();
    return;
  }
  payloadTabsController?.renderBuilderUi();
}

function setDynamicPayloadBuilderLevel(level) {
  if (payloadBuilderController?.setBuilderLevel) {
    return payloadBuilderController.setBuilderLevel(level);
  }
  return payloadTabsController?.setBuilderLevel(level) || 'beginner';
}

function setDynamicPreviewOpen(open, persist = true) {
  if (payloadPreviewController?.setPreviewOpen) {
    payloadPreviewController.setPreviewOpen(open, persist);
  }
}

function setDynamicPayloadMode(mode) {
  if (payloadStateController?.setPayloadMode) {
    return payloadStateController.setPayloadMode(mode);
  }
  return payloadTabsController?.setMode(mode) || 'payload_builder';
}

function formatDynamicPayloadSize(size) {
  return hubPayloadCore.formatPayloadSize(size);
}

function buildDynamicPayloadSourceSnapshot() {
  if (payloadStateController?.getActivePayloadSnapshot) {
    return payloadStateController.getActivePayloadSnapshot();
  }
  const mode = getDynamicPayloadMode();
  return { mode };
}

function hexToByteArray(hex) {
  return hubPayloadCore.hexToByteArray(hex);
}

function byteArrayToHex(bytes) {
  return hubPayloadCore.byteArrayToHex(bytes);
}

function normalizeCaptureHex(entry) {
  return hubPayloadCore.normalizeCaptureHex(entry);
}

function hexHasNullByte(hex) {
  return hubPayloadCore.hexHasNullByte(hex);
}

function getPwntoolsCaptureEntries(result) {
  return pwntoolsScriptController?.getCaptureEntries?.(result) || [];
}

function renderPwntoolsCaptureList() {
  pwntoolsScriptController?.renderCaptures?.();
}

function getDynamicPreviewFingerprint() {
  if (payloadPreviewController?.buildPreviewFingerprint) {
    return payloadPreviewController.buildPreviewFingerprint();
  }
  const previewApi = getPayloadPreviewApi();
  const snapshot = buildDynamicPayloadSourceSnapshot();
  return previewApi?.buildPayloadPreviewFingerprint
    ? previewApi.buildPayloadPreviewFingerprint(snapshot)
    : JSON.stringify(snapshot);
}

function createDynamicPreviewState(status = 'stale', overrides = {}) {
  if (payloadPreviewController?.createPreviewState) {
    return payloadPreviewController.createPreviewState(status, overrides);
  }
  const previewApi = getPayloadPreviewApi();
  const target = dynamicPayloadTargetLabel(getDynamicEffectivePayloadTarget());
  if (status === 'error') {
    return previewApi?.createErrorPreviewState
      ? previewApi.createErrorPreviewState(overrides.error || 'Erreur', { target, ...overrides })
      : { status: 'error', target, size: 0, previewHexDisplay: '—', previewAsciiDisplay: '—', warnings: [], ...overrides };
  }
  return previewApi?.createStalePreviewState
    ? previewApi.createStalePreviewState({ target, ...overrides })
    : { status: 'stale', target, size: 0, previewHexDisplay: '—', previewAsciiDisplay: '—', warnings: [], ...overrides };
}

function normalizeGeneratedPreview(rawResult, { mode, template = '', targetMode = '', currentPayloadSource = '' } = {}) {
  const helper = getExploitHelperApi();
  const result = rawResult || {};
  const bytes = Array.isArray(result.bytes) ? result.bytes.map((value) => Number(value) & 0xff) : [];
  const previewHex = String(result.previewHex || helper?.bytesToHex?.(bytes) || '').trim();
  return {
    mode,
    template,
    targetMode: targetMode || getDynamicInputTargetModeForPayload(),
    payloadBytesHex: previewHex,
    sourceFields: result.sourceFields || {},
    generatedSnippet: String(result.generatedSnippet || ''),
    generatedPwntoolsSnippet: String(result.generatedSnippet || ''),
    currentPayloadSource: String(currentPayloadSource || ''),
    resolvedPayloadBytes: bytes,
    size: Number(result.size ?? bytes.length) || 0,
    previewHex,
    previewAscii: String(result.previewAscii || helper?.bytesToAscii?.(bytes) || ''),
    warnings: Array.isArray(result.warnings) ? result.warnings.map(String) : [],
    payloadExpr: String(result.payloadExpr || helper?.bytesToEscaped?.(bytes) || ''),
  };
}

function renderDynamicPayloadPreview(state) {
  if (payloadPreviewController?.renderPreview) {
    payloadPreviewController.renderPreview(state);
  }
}

function invalidateDynamicPayloadPreview() {
  if (payloadStateController?.invalidatePayloadPreview) {
    return payloadStateController.invalidatePayloadPreview('generic');
  }
  if (payloadPreviewController?.markPreviewStale) {
    return payloadPreviewController.markPreviewStale();
  }
  dynamicPayloadPreviewState = createDynamicPreviewState('stale', {
    fingerprint: getDynamicPreviewFingerprint(),
  });
  renderDynamicPayloadPreview(dynamicPayloadPreviewState);
  return dynamicPayloadPreviewState;
}

function getDynamicResolvedArch() {
  if (exploitHelperController?.getResolvedArch) {
    return exploitHelperController.getResolvedArch();
  }
  const explicit = String(exploitHelperArch?.value || 'auto').toLowerCase();
  if (explicit === 'i386' || explicit === 'amd64') return explicit;
  return Number(dynamicTraceInitState.archBits) === 32 ? 'i386' : 'amd64';
}

function getDynamicInputTargetModeForPayload() {
  if (payloadStateController?.getInputTargetModeForPayload) {
    return payloadStateController.getInputTargetModeForPayload();
  }
  if (getDynamicPayloadMode() === 'file') return 'argv1';
  return getDynamicPayloadTargetMode();
}

function updateDynamicPayloadFilePanels() {
  if (filePayloadController?.refreshFilePayloadUi) {
    filePayloadController.refreshFilePayloadUi();
    return;
  }
  payloadTabsController?.renderFilePanels();
}

function updateExploitHelperTemplateFields() {
  if (exploitHelperController?.refreshExploitHelperUi) {
    exploitHelperController.refreshExploitHelperUi();
    return;
  }
  payloadTabsController?.renderHelperFields();
}

function collectExploitHelperFields() {
  if (exploitHelperController?.collectExploitHelperFields) {
    return exploitHelperController.collectExploitHelperFields();
  }
  const template = exploitHelperTemplate?.value || 'pattern';
  const archChoice = exploitHelperArch?.value || 'auto';
  const archResolved = archChoice === 'auto' ? getDynamicResolvedArch() : archChoice;
  const fields = {
    template,
    arch: archChoice === 'auto' ? archResolved : archChoice,
    archChoice,
    archResolved,
    endian: exploitHelperEndian?.value || 'little',
    badchars: exploitHelperBadchars?.value?.trim() || '',
    targetMode: getDynamicInputTargetModeForPayload(),
  };
  if (template === 'pattern') {
    fields.patternLength = document.getElementById('exploitPatternLength')?.value || '128';
    fields.crashedValue = document.getElementById('exploitPatternCrashedValue')?.value?.trim() || '';
  } else if (template === 'overwrite_variable') {
    fields.offset = document.getElementById('exploitOverwriteOffset')?.value || '0';
    fields.value = document.getElementById('exploitOverwriteValue')?.value?.trim() || '';
    fields.size = document.getElementById('exploitOverwriteSize')?.value || '4';
  } else if (template === 'ret2win') {
    fields.offset = document.getElementById('exploitRet2winOffset')?.value || '0';
    fields.winAddress = document.getElementById('exploitRet2winAddress')?.value?.trim() || '';
    fields.retGadget = document.getElementById('exploitRet2winRetGadget')?.value?.trim() || '';
  } else if (template === 'call_one_arg') {
    fields.offset = document.getElementById('exploitCallOffset')?.value || '0';
    fields.functionAddress = document.getElementById('exploitCallFunctionAddress')?.value?.trim() || '';
    fields.argumentValue = document.getElementById('exploitCallArgument')?.value?.trim() || '';
    fields.returnAddress = document.getElementById('exploitCallReturnAddress')?.value?.trim() || '';
    fields.popRdiGadget = document.getElementById('exploitCallPopRdi')?.value?.trim() || '';
  }
  return fields;
}

function buildDynamicGeneratedInput() {
  if (getDynamicPayloadMode() === 'exploit_helper') {
    if (exploitHelperController?.getExploitHelperPayload) {
      return exploitHelperController.getExploitHelperPayload();
    }
    const helper = getExploitHelperApi();
    if (!helper) throw new Error('Exploit helper indisponible.');
    const fields = collectExploitHelperFields();
    return normalizeGeneratedPreview(
      helper.generateExploitHelper(fields),
      {
        mode: 'exploit_helper',
        template: fields.template,
        targetMode: fields.targetMode,
        currentPayloadSource: JSON.stringify(fields),
      }
    );
  }
  return null;
}

function buildDynamicExploitHelperOutputText() {
  if (exploitHelperController?.buildOutputText) {
    return exploitHelperController.buildOutputText();
  }
  const generated = buildDynamicGeneratedInput();
  const parts = [];
  if (generated?.payloadExpr) parts.push(generated.payloadExpr);
  if (generated?.generatedSnippet) parts.push(generated.generatedSnippet);
  if (generated?.previewHex) parts.push(`hex: ${generated.previewHex}`);
  const warnings = Array.isArray(generated?.warnings) ? generated.warnings.filter(Boolean) : [];
  if (warnings.length) parts.push(`warnings: ${warnings.join(' | ')}`);
  return parts.join('\n\n') || '—';
}

function buildDynamicBuilderInput() {
  if (payloadBuilderController?.buildBuilderInputConfig) {
    return payloadBuilderController.buildBuilderInputConfig();
  }
  const helper = getExploitHelperApi();
  if (!helper?.buildPayload) throw new Error('Helper payload indisponible.');
  const payloadSource = String(payloadBuilderInput?.value || '').trim();
  const targetMode = getDynamicPayloadTargetMode();
  const resolved = normalizeGeneratedPreview(
    helper.buildPayload(payloadSource, getDynamicPayloadBuilderLevel(), {
      arch: getDynamicResolvedArch(),
      endian: exploitHelperController?.getEndian?.() || exploitHelperEndian?.value || 'little',
      badchars: exploitHelperController?.getBadchars?.() || exploitHelperBadchars?.value || '',
      targetMode,
    }),
    {
      mode: 'payload_builder',
      targetMode,
      currentPayloadSource: payloadSource,
    }
  );
  return {
    ...resolved,
    currentPayloadSource: payloadSource,
    payloadExpr: resolved.payloadExpr || '',
    sourceFields: {
      input: payloadSource,
      expression: payloadSource,
      builderLevel: getDynamicPayloadBuilderLevel(),
    },
  };
}

function buildDynamicFileInput() {
  if (payloadStateController?.buildActiveInputConfig) {
    return payloadStateController.buildActiveInputConfig();
  }
  const snapshot = filePayloadController?.getFilePayloadSnapshot?.() || {};
  const source = snapshot.source === 'path' ? 'path' : 'inline';
  const guestPath = String(snapshot.guestPath || '/tmp/pof-input.txt').trim() || '/tmp/pof-input.txt';
  const hostPath = String(snapshot.hostPath || '').trim();
  const inlineContent = snapshot.inlineContent || '';
  const warnings = [];
  const inlineBytes = source === 'inline' ? Array.from(new TextEncoder().encode(inlineContent)) : [];
  if (source === 'path' && !hostPath) warnings.push('Fichier local requis.');
  if (source === 'inline' && !inlineContent) warnings.push('Contenu de fichier vide.');
  const generatedSnippet = [
    'from pwn import *',
    `io = process([exe, ${JSON.stringify(guestPath)}])`,
  ].join('\n');
  return {
    mode: 'file',
    targetMode: 'argv1',
    payloadBytesHex: '',
    sourceFields: { source, guestPath, hostPath: source === 'path' ? hostPath : '', passAs: 'argv1' },
    generatedSnippet,
    generatedPwntoolsSnippet: generatedSnippet,
    currentPayloadSource: source === 'inline' ? inlineContent : hostPath,
    resolvedPayloadBytes: inlineBytes,
    size: inlineBytes.length,
    previewHex: '',
    previewAscii: source === 'inline' ? inlineContent.slice(0, 160) : hostPath,
    warnings,
    file: {
      source,
      guestPath,
      hostPath: source === 'path' ? hostPath : '',
      inlineContent: source === 'inline' ? inlineContent : '',
      passAs: 'argv1',
    },
  };
}

function buildDynamicPwntoolsInput() {
  if (payloadStateController?.buildActiveInputConfig) {
    return payloadStateController.buildActiveInputConfig();
  }
  const result = pwntoolsScriptController?.getAnalysisResult?.();
  if (!result || typeof result !== 'object') {
    throw new Error('Analyse pwntools requise avant la preview.');
  }
  const entries = getPwntoolsCaptureEntries(result);
  if (!entries.length) {
    throw new Error('Aucun payload capturé dans le script pwntools.');
  }
  const selectedCapture = pwntoolsScriptController?.getSelectedCapture?.() || null;
  const selected = entries.find((entry) => entry.id === selectedCapture?.captureId) || entries[0];
  const targetMode = selectedCapture?.target || selected.targetHint || 'stdin';
  const warnings = [
    ...(Array.isArray(result.warnings) ? result.warnings.map(String) : []),
  ];
  if (targetMode === 'argv1' && hexHasNullByte(selected.hex)) {
    warnings.push('argv[1] ne peut pas transporter un octet NUL exact.');
  }
  return {
    mode: 'pwntools_script',
    targetMode,
    payloadBytesHex: selected.hex,
    sourceFields: {
      sourceFileName: pwntoolsScriptController?.getScriptName?.() || result.sourceFileName || '',
      captureId: selected.id,
      selectedCaptureKind: selected.kind,
      target: targetMode,
      processArgs: selected.processArgs,
    },
    generatedSnippet: pwntoolsScriptController?.getScriptContent?.() || '',
    generatedPwntoolsSnippet: pwntoolsScriptController?.getScriptContent?.() || '',
    currentPayloadSource: pwntoolsScriptController?.getScriptContent?.() || '',
    resolvedPayloadBytes: hexToByteArray(selected.hex),
    size: selected.size,
    previewHex: selected.hex,
    previewAscii: selected.asciiPreview || '',
    warnings,
    payloadExpr: '',
    sourceFileName: pwntoolsScriptController?.getScriptName?.() || result.sourceFileName || '',
    selectedCaptureKind: selected.kind,
    target: targetMode,
  };
}

function buildDynamicInputConfig() {
  if (payloadStateController?.buildActiveInputConfig) {
    return payloadStateController.buildActiveInputConfig();
  }
  const mode = getDynamicPayloadMode();
  if (mode === 'payload_builder') {
    return buildDynamicBuilderInput();
  }
  if (mode === 'file') {
    return buildDynamicFileInput();
  }
  if (mode === 'exploit_helper') {
    return buildDynamicGeneratedInput();
  }
  if (mode === 'pwntools_script') {
    return buildDynamicPwntoolsInput();
  }
  throw new Error('Mode payload non supporte pour la preview.');
}

function resolveDynamicPreviewFromUi({ reason = 'manual' } = {}) {
  if (payloadPreviewController?.refreshPreview) {
    return payloadPreviewController.refreshPreview({ reason });
  }
  return null;
}

function ensureDynamicPayloadPreview() {
  if (payloadPreviewController?.ensurePreview) {
    return payloadPreviewController.ensurePreview();
  }
  return resolveDynamicPreviewFromUi();
}

function refreshDynamicPayloadPreviewAfterSelection(reason = 'selection') {
  if (payloadPreviewController?.refreshPreviewAfterSelection) {
    return payloadPreviewController.refreshPreviewAfterSelection(reason);
  }
  return null;
}

function requestDynamicTraceHistory() {
  if (payloadHistoryController?.refreshHistory) {
    payloadHistoryController.refreshHistory();
    return;
  }
  vscode.postMessage({ type: 'requestDynamicTraceHistory' });
}
