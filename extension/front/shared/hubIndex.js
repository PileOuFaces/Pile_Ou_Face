/**
 * Compatibility namespace for future hub modules.
 * hub.js remains the classic-script orchestrator.
 */
(function initHubModuleIndex(global) {
  global.POFHub = {
    ...(global.POFHub || {}),
    state: global.POFHubState,
    messageBus: global.POFHubMessageBus,
    messageRouter: global.POFHubMessageRouter,
    statusController: global.POFHubStatusController,
    payloadCore: global.POFHubPayloadCore,
    payloadBuilderController: global.POFHubPayloadBuilderController,
    payloadStateController: global.POFHubPayloadStateController,
    payloadPreviewController: global.POFHubPayloadPreviewController,
    payloadHistoryController: global.POFHubPayloadHistoryController,
    filePayloadController: global.POFHubFilePayloadController,
    exploitHelperController: global.POFHubExploitHelperController,
    pwntoolsScriptController: global.POFHubPwntoolsScriptController,
    dynamicVisualizerController: global.POFHubDynamicVisualizerController,
    runTraceController: global.POFHubRunTraceController,
    dynamicPresetController: global.POFHubDynamicPresetController,
    binarySourceController: global.POFHubBinarySourceController,
    exploitNotesController: global.POFHubExploitNotesController,
    staticToolsWidgetsController: global.POFHubStaticToolsWidgetsController,
    toastController: global.POFHubToastController,
    archBadgeController: global.POFHubArchBadgeController,
  };
})(window);
