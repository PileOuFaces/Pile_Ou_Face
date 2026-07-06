/**
 * @file hub.js
 * @brief Contrôleur du hub Pile ou Face — UI alignée MOSCOW.
 */
/* global TextEncoder */
// payloadCore.js (position 185) has loaded by now — safe to capture the reference
const hubPayloadCore = window.POFHub?.payloadCore || window.POFHubPayloadCore;

window.discoveredFunctionsCache = window.discoveredFunctionsCache || [];
window.functionListCache = window.functionListCache || [];
window.functionRadarCache = window.functionRadarCache || null;
window.functionWorkspaceState = window.functionWorkspaceState || null;

// Correspondance tab → feature(s) dans la matrice de support arch
// Tableau = on prend le niveau le plus bas parmi toutes les features
// Arch badge — moved to archBadgeController.js

// _settingsCache declared early: getStaticInterfaceMode accesses it during binarySourceController
// init (TDZ guard — actual value is set later by _applySettings).
// payloadStateController declared early: normalizeDynamicPayloadMode accesses it
// synchronously during payloadTabsController creation below (TDZ guard).
const payloadStateControllerFactory = window.POFHub?.payloadStateController || window.POFHubPayloadStateController;
let payloadStateController = null;
const payloadTabsController = window.POFHubPayloadTabsController?.create({
  document,
  initialMode: 'payload_builder',
  initialBuilderLevel: 'beginner',
  normalizeMode: normalizeDynamicPayloadMode,
  normalizeBuilderLevel: normalizePayloadBuilderLevel,
  getBuilderHint: getDynamicPayloadBuilderHint,
  getHelperOutput: buildDynamicExploitHelperOutputText,
  onRender: updateArgvPayloadHint,
  onBuilderLevelRender: updateArgvPayloadHint,
});
const payloadPreviewControllerFactory = window.POFHub?.payloadPreviewController || window.POFHubPayloadPreviewController;
let payloadPreviewController = null;
const messageRouterFactory = window.POFHub?.messageRouter || window.POFHubMessageRouter;
let messageRouter = null;
const statusControllerFactory = window.POFHub?.statusController || window.POFHubStatusController;
let statusController = null;
const payloadBuilderControllerFactory = window.POFHub?.payloadBuilderController || window.POFHubPayloadBuilderController;
let payloadBuilderController = null;
const payloadHistoryControllerFactory = window.POFHub?.payloadHistoryController || window.POFHubPayloadHistoryController;
let payloadHistoryController = null;
const filePayloadControllerFactory = window.POFHub?.filePayloadController || window.POFHubFilePayloadController;
let filePayloadController = null;
const exploitHelperControllerFactory = window.POFHub?.exploitHelperController || window.POFHubExploitHelperController;
let exploitHelperController = null;
const pwntoolsScriptControllerFactory = window.POFHub?.pwntoolsScriptController || window.POFHubPwntoolsScriptController;
let pwntoolsScriptController = null;
const dynamicVisualizerControllerFactory = window.POFHub?.dynamicVisualizerController || window.POFHubDynamicVisualizerController;
let dynamicVisualizerController = null;
const dynamicPresetControllerFactory = window.POFHub?.dynamicPresetController || window.POFHubDynamicPresetController;
let dynamicPresetController = null;
const runTraceControllerFactory = window.POFHub?.runTraceController || window.POFHubRunTraceController;
let runTraceController = null;
const binarySourceControllerFactory = window.POFHub?.binarySourceController || window.POFHubBinarySourceController;
// binarySourceController declared in binary.js (loaded earlier)
const exploitNotesControllerFactory = window.POFHub?.exploitNotesController || window.POFHubExploitNotesController;
let exploitNotesController = null;
const runtimeSessionControllerFactory = window.POFHub?.runtimeSessionController || window.POFHubRuntimeSessionController;
let runtimeSessionController = null;
const staticToolsWidgetsControllerFactory = window.POFHub?.staticToolsWidgetsController || window.POFHubStaticToolsWidgetsController;
const staticToolsWidgetsController = staticToolsWidgetsControllerFactory?.initStaticToolsWidgetsController?.() || null;
window.staticToolsWidgetsController = staticToolsWidgetsController;
const toastControllerFactory = window.POFHub?.toastController || window.POFHubToastController;
const toastController = toastControllerFactory?.initToastController?.() || null;
const archBadgeControllerFactory = window.POFHub?.archBadgeController || window.POFHubArchBadgeController;
const archBadgeController = archBadgeControllerFactory?.initArchBadgeController?.({
  getCurrentArchSupport: () => currentArchSupport,
  getTabFeatures: (tid) => TAB_FEATURE_MAP[tid] || [],
}) || null;

// localStorage helpers


// Restore last panel or use initial from body
// Nav/outils listeners registered in nav.js, outils.js at top level

// Static: binary path shared with dynamic form

binarySourceController = binarySourceControllerFactory?.initBinarySourceController?.({
  postMessage: (msg) => vscode.postMessage(msg),
  staticBinaryInput,
  binaryPathInput,
  dynamicSourcePathInput,
  form,
  _loadStorage,
  _saveStorage,
  _normalizeRawProfile,
  _displayRawArchName,
  _displayEndianName,
  _basenameFromPath,
  clearCrossAnalysisResolutionCache: typeof clearCrossAnalysisResolutionCache === 'function' ? clearCrossAnalysisResolutionCache : undefined,
  syncNavigationHistoryForBinary,
  syncToolsBinaryLabel,
  renderBookmarks,
  showGroup,
  getActiveStaticTab,
  syncStaticWorkspaceSummary: () => syncStaticWorkspaceSummary(),
  updateActiveContextBars: (addr) => updateActiveContextBars(addr),
  resetStaticBinaryDerivedState,
  requestSymbols,
  requestRunTraceInit: (preset, path) => requestRunTraceInit(preset, path),
  setDynamicTraceStatus,
  updateArgvPayloadHint,
  showPanel,
  getPendingStaticQuickAction: () => pendingStaticQuickAction,
  setPendingStaticQuickAction: (v) => { pendingStaticQuickAction = v; },
  triggerStaticQuickAction,
  _autoLoadTab,
  getSectionsCacheBinaryPath: () => tabDataCache.sections?.binaryPath,
}) || null;

// Restore static binary path from storage
try {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved) {
    const { staticBinaryPath, binaryMeta } = JSON.parse(saved);
    if (staticBinaryPath && staticBinaryInput) {
      staticBinaryInput.value = staticBinaryPath;
      if (binaryPathInput && !binaryPathInput.value?.trim()) binaryPathInput.value = staticBinaryPath;
      currentBinaryMeta = _normalizeBinaryMeta(binaryMeta || null);
      updateTopBarBinaryDisplay(staticBinaryPath, currentBinaryMeta);
    }
  }
} catch (_) {}


// Short aliases injected into payloadStateController as dep names.

messageRouter = messageRouterFactory?.initMessageRouter?.({});

statusController = statusControllerFactory?.initStatusController?.({
  document,
  dynamicTraceStatus,
});

dynamicVisualizerController = dynamicVisualizerControllerFactory?.initDynamicVisualizerController?.({
  postMessage: (message) => vscode.postMessage(message),
  setDynamicTraceStatus,
});

payloadBuilderController = payloadBuilderControllerFactory?.initPayloadBuilderController?.({
  payloadBuilderInput,
  getBuilderLevel: () => payloadTabsController?.getBuilderLevel?.() || 'beginner',
  setBuilderLevel: (level) => payloadTabsController?.setBuilderLevel?.(level) || 'beginner',
  renderBuilderUi: () => payloadTabsController?.renderBuilderUi?.(),
  normalizePayloadBuilderLevel,
  getDynamicPayloadTargetMode,
  getDynamicResolvedArch,
  getEndian: () => exploitHelperController?.getEndian?.() || exploitHelperEndian?.value || 'little',
  getBadchars: () => exploitHelperController?.getBadchars?.() || exploitHelperBadchars?.value || '',
  getExploitHelperApi,
  parsePayloadExpressionPreview,
  normalizeGeneratedPreview,
  dynamicPayloadTargetLabel,
  getDynamicEffectivePayloadTarget,
  updateArgvPayloadHint,
  invalidateDynamicPayloadPreview,
  setDynamicTraceStatus,
});

filePayloadController = filePayloadControllerFactory?.initFilePayloadController?.({
  postMessage: (message) => vscode.postMessage(message),
  payloadFileSource,
  payloadFileGuestPath,
  payloadFileHostPath,
  payloadFileContent,
  btnDynamicSelectPayloadFile: document.getElementById('btnDynamicSelectPayloadFile'),
  setDynamicPayloadMode,
  invalidateDynamicPayloadPreview,
  refreshFilePanels: () => payloadTabsController?.renderFilePanels?.(),
  setDynamicTraceStatus,
});

exploitHelperController = exploitHelperControllerFactory?.initExploitHelperController?.({
  document,
  navigator,
  exploitHelperTemplate,
  exploitHelperArch,
  exploitHelperEndian,
  exploitHelperBadchars,
  getTraceArchBits: () => Number(dynamicTraceInitState.archBits) === 32 ? 32 : 64,
  getDynamicPayloadMode,
  getDynamicInputTargetModeForPayload,
  getExploitHelperApi,
  normalizeGeneratedPreview,
  renderHelperFields: () => payloadTabsController?.renderHelperFields?.(),
  renderHelperOutput: () => payloadTabsController?.renderHelperOutput?.(),
  invalidateDynamicPayloadPreview,
  setDynamicTraceStatus,
});

pwntoolsScriptController = pwntoolsScriptControllerFactory?.initPwntoolsScriptController?.({
  postMessage: (message) => vscode.postMessage(message),
  btnDynamicImportPwntoolsScript,
  btnAnalyzePwntoolsScript,
  payloadPwntoolsSourceLabel,
  payloadPwntoolsScriptInput,
  payloadPwntoolsScriptWarning,
  payloadPwntoolsCaptureList,
  getBinaryPath: () => String(binaryPathInput?.value || '').trim(),
  setDynamicTraceStatus,
  setDynamicPayloadMode,
  updateArgvPayloadHint,
  invalidateDynamicPayloadPreview,
  refreshDynamicPayloadPreviewAfterSelection,
  normalizeCaptureHex,
  hexToByteArray,
  debugDynamicPayload,
  renderWarnings: (warnings, options) => statusController?.renderWarnings?.(warnings, options),
});

payloadStateController = payloadStateControllerFactory?.initPayloadStateController?.({
  document,
  TextEncoder: window.TextEncoder,
  normalizePayloadMode: (mode) => hubPayloadCore.normalizePayloadMode(mode),
  normalizePayloadTargetMode,
  normalizeEffectiveTarget,
  payloadTargetLabel: dynamicPayloadTargetLabel,
  payloadTabsController,
  dynamicPayloadTargetMode,
  getDynamicTraceInitState,
  markPreviewStale: () => payloadPreviewController?.markPreviewStale?.(),
  renderPreview: (state) => payloadPreviewController?.renderPreview?.(state),
  createPreviewState: (status, overrides) => payloadPreviewController?.createPreviewState?.(status, overrides),
  getPreviewFingerprint: () => payloadPreviewController?.buildPreviewFingerprint?.() || getDynamicPreviewFingerprint(),
  payloadBuilderController,
  filePayloadController,
  exploitHelperController,
  pwntoolsScriptController,
  getDynamicResolvedArch,
  getPwntoolsCaptureEntries: (result) => pwntoolsScriptController?.getCaptureEntries?.(result) || [],
  hexHasNullByte,
  hexToByteArray,
});

payloadPreviewController = payloadPreviewControllerFactory?.initPayloadPreviewController?.({
  document,
  navigator,
  storageKey: POF_PREVIEW_OPEN_KEY,
  dynamicPreviewCard,
  dynamicPreviewCardHeader,
  dynamicPreviewCardBody,
  dynamicPreviewToggleLabel,
  payloadPreviewStatus,
  payloadPreviewTarget,
  payloadPreviewSize,
  payloadPreviewHex,
  payloadPreviewAscii,
  payloadPreviewTruncated,
  payloadPreviewSnippetDetails,
  payloadPwntoolsSnippet,
  payloadPreviewWarnings,
  btnPayloadPreview: document.getElementById('btnPayloadPreview'),
  btnPayloadUseGenerated: document.getElementById('btnPayloadUseGenerated'),
  btnPayloadCopyPwntools: document.getElementById('btnPayloadCopyPwntools'),
  payloadBuilderInput,
  getPayloadPreviewApi,
  getDynamicPayloadPreviewState,
  setDynamicPayloadPreviewState,
  buildDynamicPayloadSourceSnapshot,
  buildDynamicInputConfig,
  dynamicPayloadTargetLabel,
  getDynamicEffectivePayloadTarget,
  getDynamicInputTargetModeForPayload,
  getDynamicPayloadMode,
  setDynamicPayloadMode,
  setDynamicPayloadBuilderLevel,
  formatDynamicPayloadSize,
  updateArgvPayloadHint,
  setDynamicTraceStatus,
  debugDynamicPayload,
  renderWarnings: (warnings, options) => statusController?.renderWarnings?.(warnings, options),
});

payloadHistoryController = payloadHistoryControllerFactory?.initPayloadHistoryController?.({
  document,
  postMessage: (message) => vscode.postMessage(message),
  dynamicTraceHistory,
  btnRefreshDynamicTraceHistory,
  btnClearDynamicTraceHistory,
  getDynamicTraceHistoryState,
  setDynamicTraceHistoryState,
  setDynamicTraceStatus,
  getBinaryPath: () => String(binaryPathInput?.value || '').trim(),
  runBtn,
  openVisualizer: (traceOrPath, options) => dynamicVisualizerController?.openVisualizer?.(traceOrPath, options),
});

dynamicPresetController = dynamicPresetControllerFactory?.initDynamicPresetController?.({
  postMessage: (message) => vscode.postMessage(message),
  showPanel,
  requestRunTraceInit,
  getDynamicPayloadTargetMode,
  normalizeDynamicPayloadTargetMode,
  dynamicPayloadTargetMode,
  runBtn,
  getDynamicTraceInitState,
  getStaticBinaryPath,
  form,
});

runTraceController = runTraceControllerFactory?.initRunTraceController?.({
  document,
  postMessage: (message) => vscode.postMessage(message),
  form,
  runBtn,
  binaryPathInput,
  dynamicArchBits,
  dynamicPie,
  dynamicSourcePathInput,
  dynamicSourceHint,
  dynamicPayloadTargetMode,
  payloadBuilderInput,
  btnDynamicSelectBinary: document.getElementById('btnDynamicSelectBinary'),
  btnDynamicSelectSource: document.getElementById('btnDynamicSelectSource'),
  getDynamicTraceInitState,
  setDynamicTraceInitState,
  getDynamicPayloadPreviewState,
  setDynamicPayloadPreviewState,
  normalizeDynamicPayloadTargetMode,
  normalizeDynamicEffectiveTarget,
  dynamicPayloadTargetLabel,
  getDynamicPayloadTargetMode,
  getDynamicPayloadMode,
  getDynamicEffectivePayloadTarget,
  buildDynamicSourceHintText,
  setDynamicTraceStatus,
  setTraceField,
  updateArgvPayloadHint,
  invalidateDynamicPayloadPreview,
  refreshDynamicTraceHistory: () => payloadHistoryController?.refreshHistory?.(),
  requestSymbols,
  ensureDynamicPayloadPreview,
  getDynamicPreviewFingerprint,
  createDynamicPreviewState,
  renderDynamicPayloadPreview,
  debugDynamicPayload,
});

exploitNotesController = exploitNotesControllerFactory?.initExploitNotesController?.({ document });

runtimeSessionController = runtimeSessionControllerFactory?.initRuntimeSessionController?.({
  document,
  postMessage: (message) => vscode.postMessage(message),
  showPanel,
  fallbackRenderer: window.POFHub?.runtimeFallbackRenderer || window.POFHubRuntimeFallbackRenderer,
});

messageRouter?.registerController(binarySourceController);
messageRouter?.registerController(dynamicVisualizerController);
messageRouter?.registerController(payloadHistoryController);
messageRouter?.registerController(filePayloadController);
messageRouter?.registerController(pwntoolsScriptController);
messageRouter?.registerController(payloadPreviewController);
messageRouter?.registerController(runTraceController);
messageRouter?.registerController(statusController);
messageRouter?.registerController(runtimeSessionController);






payloadTabsController?.bindEvents({
  onTabClick: invalidateDynamicPayloadPreview,
  onFileSourceChange: () => {
    filePayloadController?.refreshFilePayloadUi?.();
    invalidateDynamicPayloadPreview();
  },
  onHelperTemplateChange: invalidateDynamicPayloadPreview,
  onBuilderLevelClick: invalidateDynamicPayloadPreview,
});

// Disasm nav / search / export listeners registered in search.js at top level

/**
 * Renders an interactive SVG graph (CFG or Call Graph).
 * Features: zoom/pan (via initCfgZoom), node drag, Shift+click BFS path highlight.
 *
 * @param {Array<{addr:string, label?:string, sublabel?:string, lines?:Array}>} nodes
 * @param {Array<{from:string, to:string, type?:string}>} edges
 * @param {{nodeW?:number, nodeH?:number, padX?:number, padY?:number, lanePadX?:number,
 *          onNodeClick?:Function, zoomState?:{scale:number}}} opts
 * @returns {SVGElement}
 */

// Offset calculator
// Offset calculator — moved to staticToolsWidgetsController.js

staticToolsWidgetsController?.init();

// Init event listeners by module
initMessageHandler();
initSettingsListeners();
initSearchListeners();
initStaticToolsListeners();
initHexListeners();
if (typeof initCrossAnalysisListeners === 'function') initCrossAnalysisListeners();
initDynamicListeners();
initSharedWidgetsListeners();

// Platform
vscode.postMessage({ type: 'getPlatform' });
vscode.postMessage({ type: 'hubLoadPluginState' });
vscode.postMessage({ type: 'hubRequestRecentBinaries' });

// Sidebar, bookmarks, nav history listeners registered in settings.js at top level

// Initial render
_migrateDisabledFamilies();
renderBookmarks();
initDisasmUxState();

// Init
initExploitNotesWidget();
initOllamaChatWidget();
injectActiveContextBars();
initPanel();
vscode.postMessage({ type: 'pof.auth.getState' });
syncDynamicBinaryFieldMode();
vscode.postMessage({ type: 'listGeneratedFiles' });

syncToolsBinaryLabel();
syncStaticWorkspaceSummary();
renderPluginManager(pluginUiState);
renderRecentBinaries();
updateArgvPayloadHint();
setDynamicPayloadMode('payload_builder');
setDynamicPayloadBuilderLevel('beginner');
invalidateDynamicPayloadPreview();
const savedOllamaBaseUrl = String(_loadStorage().ollamaBaseUrl || '').trim();
if (savedOllamaBaseUrl) {
  const baseUrlInput = document.getElementById('ollamaBaseUrl');
  if (baseUrlInput) baseUrlInput.value = savedOllamaBaseUrl;
}
hydrateOllamaConversationHistory();
renderOllamaModels([], ollamaUiState.lastModel || '');
renderOllamaConversation();
renderOllamaConversationHistory();
requestOllamaModels();
vscode.postMessage({ type: 'hubReady' });

// Initialize plugin iframe router and register all plugin frames
if (window.PluginIframeRouter) {
  window.PluginIframeRouter.init(window, vscode);
  document.querySelectorAll('iframe.plugin-iframe').forEach(function (frame) {
    var slug = frame.dataset.pluginSlug;
    if (slug) window.PluginIframeRouter.register(slug, frame);
  });
}

// À l'ouverture : si le panel dynamic n'était pas déjà affiché (auquel cas showPanel l'a déjà init),
// pré-charger le profil binaire pour que la tab soit prête quand l'utilisateur la bascule.
const _dynamicAlreadyInit = document.getElementById('panel-dynamic')?.classList.contains('active') ?? false;
if (!_dynamicAlreadyInit) {
  const initialBp = getStaticBinaryPath();
  const initialPanelId = document.body.dataset.initialPanel || 'dashboard';
  if (initialBp) {
    requestRunTraceInit(null, initialBp);
  } else if (initialPanelId === 'dynamic') {
    requestRunTraceInit();
  }
}

updateTabOverflow();
