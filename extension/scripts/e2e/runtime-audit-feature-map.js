// SPDX-License-Identifier: AGPL-3.0-only

const RESPONSE_TYPES_BY_MESSAGE = {
  compilerListRequest: ['compilerListResult'],
  getPlatform: ['platformInfo'],
  listGeneratedFiles: ['generatedFiles'],
  hubReady: ['hubPerfDiagnosticsConfig'],
  hubGetSettings: ['hubSettings'],
  hubListDecompilers: ['hubDecompilerList'],
  hubLoadPluginState: ['hubPluginState'],
  hubOllamaListModels: ['hubOllamaModels'],
  hubOpenDisasm: ['hubDisasmReady'],
  hubRequestRecentBinaries: ['hubSetRecentBinaries'],
  hubLoadAnnotations: ['hubAnnotations'],
  hubSaveAnnotation: ['hubAnnotationSaved'],
  hubSaveBookmark: ['hubAnnotationSaved'],
  hubSaveFunctionReview: ['hubAnnotationSaved'],
  hubDeleteBookmark: ['hubAnnotationSaved'],
  hubClearBookmarks: ['hubAnnotationSaved'],
  hubDeleteAnnotation: ['hubAnnotationSaved'],
  hubUseBinaryPath: ['hubSetBinaryPath'],
  hubLoadInfo: ['hubBinaryInfo'],
  hubLoadSections: ['hubSections'],
  hubLoadSymbols: ['hubSymbols'],
  hubLoadStrings: ['hubStrings'],
  hubLoadXrefs: ['hubXrefs'],
  hubLoadCfg: ['hubCfg'],
  hubLoadCfgForAddr: ['hubCfg'],
  hubLoadCallGraph: ['hubCallGraph'],
  hubLoadDiscoveredFunctions: ['hubDiscoveredFunctions'],
  hubLoadImports: ['hubImportsDone'],
  hubLoadExports: ['hubExportsDone'],
  hubLoadImportXrefs: ['hubImportXrefsDone'],
  hubLoadHexView: ['hubHexView'],
  hubLoadPatches: ['hubPatchesDone'],
  hubLoadStackFrame: ['hubStackFrame'],
  hubLoadFunctions: ['hubFunctionsDone'],
  hubLoadDecompile: ['hubDecompileStatus'],
  hubLoadPeResources: ['hubPeResourcesDone'],
  hubLoadExceptionHandlers: ['hubExceptionHandlersDone'],
  hubLoadTypedData: ['hubTypedDataDone'],
  hubPreviewTypedStruct: ['hubTypedStructPreviewDone'],
  hubLoadStructs: ['hubStructsDone'],
  hubSaveStructs: ['hubStructsSaved'],
  hubSaveTypedStructRef: ['hubTypedStructRefSaved'],
  hubPayloadToHex: ['hubPayloadHex'],
  hubAutoFromCmp: ['hubAutoFromCmpResult'],
  hubRunScript: ['hubScriptResult'],
  hubSaveScript: ['hubScriptSaved'],
  hubLoadScript: ['hubScriptLoaded'],
  hubAnalyzePwntoolsScript: ['hubPwntoolsScriptAnalyzed'],
  hubSearchBinary: ['hubRecherche'],
  hubAiProvidersGet: ['hubAiProvidersResult'],
  hubAiProviderSet: ['hubAiProvidersResult'],
  hubAiProviderTest: ['hubAiProvidersResult'],
  hubAiProviderDefaultSet: ['hubAiProviderDefaultSaved'],
  hubAiProviderPrompt: ['hubOllamaResult'],
  hubCompileStaticBinary: ['hubStaticCompileDone'],
  runTrace: ['runTraceDone'],
  hubPickFile: ['hubPickedFile'],
  hubExecuteCommand: ['hubCommandResult'],
  hubListRules: ['hubRulesList'],
  hubAddUserRule: ['hubRuleAdded'],
  hubBrowseImportRule: ['hubRuleImported'],
  hubGetRuleContent: ['hubRuleContent'],
  hubToggleRule: ['hubRuleToggled'],
  hubUpdateUserRule: ['hubRuleUpdated'],
  hubDeleteUserRule: ['hubRuleDeleted'],
  hubPatchBytes: ['hubPatchResult'],
  hubRedoPatch: ['hubRedoPatchDone'],
  hubRevertPatch: ['hubRevertPatchDone'],
  hubRevertAllPatches: ['hubRevertPatchDone'],
  hubForgetRecentBinary: ['generatedFiles'],
  hubGrantPluginConsent: ['hubPluginState'],
  hubPluginInvoke: ['hubPluginResult'],
  hubInstallPlugin: ['hubPluginInstalled'],
  hubPullDecompilerImage: ['hubDecompilerPullDone'],
  hubOpenPluginDirectory: ['hubPluginFolderOpened'],
  hubOllamaPrompt: ['hubOllamaResult'],
  hubResetSettings: ['hubSettings'],
  hubSaveSettings: ['hubSettingsSaved'],
  'pof.auth.login': ['accountState'],
  'pof.auth.getState': ['accountState'],
  'pof.auth.logout': ['accountState'],
  requestDynamicTraceHistory: ['dynamicTraceHistory'],
  clearDynamicTraceHistory: ['dynamicTraceHistory'],
  openDynamicTraceHistory: ['dynamicTraceHistory'],
  deleteDynamicTraceHistory: ['dynamicTraceHistory'],
};

const UI_CONSUMED_REQUIRED_MESSAGES = new Set([
  'hubLoadInfo',
  'hubLoadSections',
  'hubLoadSymbols',
  'hubLoadStrings',
  'hubLoadXrefs',
  'hubLoadCallGraph',
  'hubLoadDiscoveredFunctions',
  'hubLoadImports',
  'hubLoadExports',
  'hubLoadImportXrefs',
  'hubLoadHexView',
  'hubLoadPatches',
  'hubLoadStackFrame',
  'hubLoadFunctions',
  'hubLoadDecompile',
  'hubLoadPeResources',
  'hubLoadExceptionHandlers',
  'hubLoadTypedData',
  'hubPreviewTypedStruct',
  'hubLoadStructs',
  'hubPayloadToHex',
  'hubAutoFromCmp',
  'hubRunScript',
  'hubAiProvidersGet',
  'hubAiProviderPrompt',
  'hubCompileStaticBinary',
]);

const BUSINESS_ASSERTION_TARGETS = {
  hubLoadInfo: 'Assert binary metadata fields: format, architecture, entry point, file size.',
  hubLoadSections: 'Assert non-empty section list and at least one executable/text section for ELF fixtures.',
  hubLoadSymbols: 'Assert expected symbols from compiled fixtures, including main-like entry candidates.',
  hubLoadStrings: 'Assert expected fixture strings and minimum extraction metadata.',
  hubLoadCfg: 'Assert CFG has entry block and stable edge shape for fixture function.',
  hubLoadCfgForAddr: 'Assert address-scoped CFG resolves the selected function.',
  hubLoadCallGraph: 'Assert call graph contains expected fixture function nodes/edges.',
  hubLoadDiscoveredFunctions: 'Assert discovered function count and known fixture addresses.',
  hubLoadFunctions: 'Assert function rows, calling convention/radar payload shape.',
  hubLoadHexView: 'Assert byte ranges match the fixture file content.',
  hubLoadImports: 'Assert libc/toolchain imports for dynamic fixtures or empty result for static fixtures.',
  hubLoadExports: 'Assert exports payload shape and no parse error.',
  hubLoadPatches: 'Assert patch list state before and after patch mutation.',
  hubPatchBytes: 'Assert patched byte persisted in disposable binary copy.',
  runTrace: 'Assert successful dynamicTraceReady with snapshots, diagnostics, history persistence, and UI render.',
  requestDynamicTraceHistory: 'Assert history contains the trace created during the workflow.',
  clearDynamicTraceHistory: 'Assert history is empty after clear and active trace is reset.',
  hubAiProviderPrompt: 'Assert mocked provider token stream and final usage payload.',
  hubOllamaPrompt: 'Assert mocked Ollama token stream and final usage payload.',
  'pof.auth.login': 'Assert mocked account state includes logged-in identity and plugin state refresh.',
  'pof.auth.logout': 'Assert account state is logged out and secrets are cleared.',
};

const PAYLOAD_ASSERTIONS_BY_MESSAGE = {
  compilerListRequest: [
    { responseType: 'compilerListResult', requiredKeys: ['compilers'] },
  ],
  getPlatform: [
    { responseType: 'platformInfo', requiredKeys: ['platform'] },
  ],
  listGeneratedFiles: [
    { responseType: 'generatedFiles', requiredKeys: ['files'] },
  ],
  hubRequestRecentBinaries: [
    { responseType: 'hubSetRecentBinaries', requiredKeys: ['recent'] },
  ],
  hubLoadInfo: [
    { responseType: 'hubBinaryInfo', requiredKeys: ['binaryPath', 'info'] },
  ],
  hubReady: [
    { responseType: 'hubPerfDiagnosticsConfig', requiredKeys: ['enabled'] },
  ],
  hubGetSettings: [
    { responseType: 'hubSettings', requiredKeys: ['settings'] },
  ],
  hubListDecompilers: [
    { responseType: 'hubDecompilerList', requiredKeys: ['result'] },
  ],
  hubLoadPluginState: [
    { responseType: 'hubPluginState', requiredKeys: ['state'] },
  ],
  hubOllamaListModels: [
    { responseType: 'hubOllamaModels', requiredKeys: ['models', 'baseUrl', 'preferredModel'], allowErrors: true },
  ],
  hubOpenDisasm: [
    { responseType: 'hubDisasmReady', requiredKeys: ['binaryPath', 'arch', 'functionAddrs'] },
  ],
  hubSaveAnnotation: [
    { responseType: 'hubAnnotationSaved', requiredKeys: ['binaryPath'] },
  ],
  hubSaveBookmark: [
    { responseType: 'hubAnnotationSaved', requiredKeys: ['binaryPath'] },
  ],
  hubSaveFunctionReview: [
    { responseType: 'hubAnnotationSaved', requiredKeys: ['binaryPath'] },
  ],
  hubDeleteBookmark: [
    { responseType: 'hubAnnotationSaved', requiredKeys: ['binaryPath'] },
  ],
  hubClearBookmarks: [
    { responseType: 'hubAnnotationSaved', requiredKeys: ['binaryPath'] },
  ],
  hubDeleteAnnotation: [
    { responseType: 'hubAnnotationSaved', requiredKeys: ['binaryPath'] },
  ],
  hubUseBinaryPath: [
    { responseType: 'hubSetBinaryPath', requiredKeys: ['binaryPath'] },
  ],
  hubLoadSections: [
    { responseType: 'hubSections', requiredKeys: ['binaryPath', 'sections'], minCounts: { sectionsCount: 1 } },
  ],
  hubLoadSymbols: [
    { responseType: 'hubSymbols', requiredKeys: ['binaryPath', 'symbols'] },
  ],
  hubLoadStrings: [
    { responseType: 'hubStrings', requiredKeys: ['binaryPath', 'strings'], minCounts: { stringsCount: 1 } },
  ],
  hubLoadXrefs: [
    { responseType: 'hubXrefs', requiredKeys: ['binaryPath', 'refs', 'targets'] },
  ],
  hubLoadCfg: [
    { responseType: 'hubCfg', requiredKeys: ['binaryPath', 'cfg', 'functions'], minCounts: { 'cfg.blocksCount': 1 } },
  ],
  hubLoadCfgForAddr: [
    { responseType: 'hubCfg', requiredKeys: ['binaryPath', 'cfg', 'functions'], minCounts: { 'cfg.blocksCount': 1 } },
  ],
  hubLoadCallGraph: [
    { responseType: 'hubCallGraph', requiredKeys: ['binaryPath', 'callGraph'] },
  ],
  hubLoadDiscoveredFunctions: [
    { responseType: 'hubDiscoveredFunctions', requiredKeys: ['binaryPath', 'functions'], minCounts: { functionsCount: 1 } },
  ],
  hubLoadImports: [
    { responseType: 'hubImportsDone', requiredKeys: ['binaryPath', 'data'] },
  ],
  hubLoadExports: [
    { responseType: 'hubExportsDone', requiredKeys: ['binaryPath', 'data'] },
  ],
  hubLoadHexView: [
    { responseType: 'hubHexView', requiredKeys: ['binaryPath', 'result'], minCounts: { 'result.rowsCount': 1 } },
  ],
  hubLoadPatches: [
    { responseType: 'hubPatchesDone', requiredKeys: ['binaryPath', 'data'] },
  ],
  hubLoadFunctions: [
    { responseType: 'hubFunctionsDone', requiredKeys: ['binaryPath', 'data'] },
  ],
  hubPatchBytes: [
    { responseType: 'hubPatchResult', requiredKeys: ['binaryPath', 'result'], exactFields: { resultOk: true } },
  ],
  runTrace: [
    { responseType: 'dynamicTraceHistory', requiredKeys: ['activeTracePath', 'items'], minCounts: { itemsCount: 1 } },
  ],
  requestDynamicTraceHistory: [
    { responseType: 'dynamicTraceHistory', requiredKeys: ['activeTracePath', 'items'], minCounts: { itemsCount: 1 } },
  ],
  clearDynamicTraceHistory: [
    { responseType: 'dynamicTraceHistory', requiredKeys: ['activeTracePath', 'items'], maxCounts: { itemsCount: 0 } },
  ],
  openDynamicTraceHistory: [
    { responseType: 'dynamicTraceHistory', requiredKeys: ['activeTracePath', 'items'] },
  ],
  deleteDynamicTraceHistory: [
    { responseType: 'dynamicTraceHistory', requiredKeys: ['activeTracePath', 'items'] },
  ],
  hubAiProvidersGet: [
    { responseType: 'hubAiProvidersResult', requiredKeys: ['data'] },
  ],
  hubAiProviderSet: [
    { responseType: 'hubAiProvidersResult', requiredKeys: ['data'] },
  ],
  hubAiProviderTest: [
    { responseType: 'hubAiProvidersResult', requiredKeys: ['data'] },
  ],
  hubAiProviderDefaultSet: [
    { responseType: 'hubAiProviderDefaultSaved', requiredKeys: ['data'] },
  ],
  hubAiProviderPrompt: [
    { responseType: 'hubOllamaResult', requiredKeys: ['model', 'output', 'requestId', 'usage'], exactFields: { ok: true } },
  ],
  hubAnalyzePwntoolsScript: [
    { responseType: 'hubPwntoolsScriptAnalyzed', requiredKeys: ['result'], allowErrors: true },
  ],
  hubSearchBinary: [
    { responseType: 'hubRecherche', requiredKeys: ['binaryPath', 'results'], minCounts: { resultsCount: 1 } },
  ],
  hubSaveScript: [
    { responseType: 'hubScriptSaved', requiredKeys: ['path'] },
  ],
  hubSaveStructs: [
    { responseType: 'hubStructsSaved', requiredKeys: ['data'] },
  ],
  hubSaveTypedStructRef: [
    { responseType: 'hubTypedStructRefSaved', requiredKeys: ['data'] },
  ],
  hubPickFile: [
    { responseType: 'hubPickedFile', requiredKeys: ['path', 'target'] },
  ],
  hubExecuteCommand: [
    { responseType: 'hubCommandResult', requiredKeys: ['command', 'requestId', 'status'] },
  ],
  hubListRules: [
    { responseType: 'hubRulesList', requiredKeys: ['rules'] },
  ],
  hubAddUserRule: [
    { responseType: 'hubRuleAdded', requiredKeys: ['rule_id'] },
  ],
  hubBrowseImportRule: [
    { responseType: 'hubRuleImported', requiredKeys: ['results'], minCounts: { resultsCount: 1 } },
  ],
  hubGetRuleContent: [
    { responseType: 'hubRuleContent', requiredKeys: ['error', 'rule'], allowErrors: true },
  ],
  hubToggleRule: [
    { responseType: 'hubRuleToggled', requiredKeys: ['error', 'success'], allowErrors: true },
  ],
  hubUpdateUserRule: [
    { responseType: 'hubRuleUpdated', requiredKeys: ['error'], allowErrors: true },
  ],
  hubDeleteUserRule: [
    { responseType: 'hubRuleDeleted', requiredKeys: ['error', 'success'], allowErrors: true },
  ],
  hubForgetRecentBinary: [
    { responseType: 'generatedFiles', requiredKeys: ['files'] },
  ],
  hubGrantPluginConsent: [
    { responseType: 'hubPluginState', requiredKeys: ['state'] },
  ],
  hubPluginInvoke: [
    { responseType: 'hubPluginResult', requiredKeys: ['feature', 'plugin_id', 'requestId', 'result'], allowErrors: true },
  ],
  hubInstallPlugin: [
    { responseType: 'hubPluginInstalled', requiredKeys: ['ok', 'scope'], allowErrors: true },
  ],
  hubPullDecompilerImage: [
    { responseType: 'hubDecompilerPullDone', requiredKeys: ['ok', 'decompiler'], allowErrors: true },
  ],
  hubOpenPluginDirectory: [
    { responseType: 'hubPluginFolderOpened', requiredKeys: ['ok', 'scope', 'path'] },
  ],
  hubOllamaPrompt: [
    { responseType: 'hubOllamaResult', requiredKeys: ['model', 'output', 'requestId', 'usage'], exactFields: { ok: true } },
  ],
  hubResetSettings: [
    { responseType: 'hubSettings', requiredKeys: ['settings'] },
  ],
  hubSaveSettings: [
    { responseType: 'hubSettingsSaved', requiredKeys: ['ok'], exactFields: { ok: true } },
  ],
  'pof.auth.login': [
    { responseType: 'accountState', requiredKeys: ['email', 'error', 'loggedIn', 'plugins'], exactFields: { loggedIn: true } },
  ],
  'pof.auth.getState': [
    { responseType: 'accountState', requiredKeys: ['loggedIn'], exactFields: { loggedIn: false } },
  ],
  'pof.auth.logout': [
    { responseType: 'accountState', requiredKeys: ['loggedIn'], exactFields: { loggedIn: false } },
  ],
};

function responseTypesForMessage(messageType) {
  return RESPONSE_TYPES_BY_MESSAGE[messageType] || [];
}

function requiresUiConsumed(messageType) {
  return UI_CONSUMED_REQUIRED_MESSAGES.has(messageType);
}

function businessAssertionForTarget(target) {
  return BUSINESS_ASSERTION_TARGETS[target] || '';
}

function payloadAssertionsForMessage(messageType) {
  return PAYLOAD_ASSERTIONS_BY_MESSAGE[messageType] || [];
}

function expectedFeatureRows(targets) {
  return targets.map((target) => ({
    target,
    expectedResponses: responseTypesForMessage(target),
    requiresUiConsumed: requiresUiConsumed(target),
    businessAssertion: businessAssertionForTarget(target),
    payloadAssertions: payloadAssertionsForMessage(target),
  }));
}

module.exports = {
  BUSINESS_ASSERTION_TARGETS,
  PAYLOAD_ASSERTIONS_BY_MESSAGE,
  RESPONSE_TYPES_BY_MESSAGE,
  UI_CONSUMED_REQUIRED_MESSAGES,
  businessAssertionForTarget,
  expectedFeatureRows,
  payloadAssertionsForMessage,
  requiresUiConsumed,
  responseTypesForMessage,
};
