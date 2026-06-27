/**
 * @file state.js
 * @brief Etat en memoire partage par la webview.
 * @details Stocke trace et curseur UI pour des renderers stateless.
 */
/**
 * @brief Etat global de la webview.
 */
export const state = {
  traceRunId: null,
  currentTraceId: null,
  snapshots: [],
  risks: [],
  diagnostics: [],
  crash: null,
  meta: {},
  binaryMetadata: null,
  disasmLines: [],
  disasmFileText: '',
  disasmFileLines: [],
  disasmFilePath: null,
  memoryMap: null,
  debugMemory: false,
  analysis: null,
  analysisByStep: {},
  enrichment: { byStep: {} },
  mcp: {
    model: null,
    analysis: null,
    explanation: null,
    byStep: {}
  },
  lastRequestedAnalysisStep: null,
  currentStep: 1,
  visibleSteps: [],
  showAllTrace: false,
  stackViewMode: 'frame',
  stackPanelMode: 'simple',
  selectedFunction: '',
  selectedStackSlotKey: null,
  lastHighlightedLine: null,
  lastDisasmLine: null,
  simStackMode: false,
  stackWorkspace: null
};
