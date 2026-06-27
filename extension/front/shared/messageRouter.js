/**
 * Classic-script controller for central hub webview message routing.
 * Keeps routing order explicit and stops propagation on first handled message.
 */
(function initHubMessageRouter(global) {
  function initMessageRouter(_deps) {
    const controllers = [];

    /**
     * @param {HubController} controller
     * @returns {HubController}
     */
    function registerController(controller) {
      if (!controller) return controller;
      controllers.push(controller);
      return controller;
    }

    function resolveHandler(controller) {
      if (!controller || typeof controller !== 'object') return null;
      if (typeof controller.handleMessage === 'function') return controller.handleMessage.bind(controller);
      if (typeof controller.handleBinarySourceMessage === 'function') return controller.handleBinarySourceMessage.bind(controller);
      if (typeof controller.handleVisualizerMessage === 'function') return controller.handleVisualizerMessage.bind(controller);
      if (typeof controller.handleHistoryMessage === 'function') return controller.handleHistoryMessage.bind(controller);
      if (typeof controller.handleFilePayloadMessage === 'function') return controller.handleFilePayloadMessage.bind(controller);
      if (typeof controller.handlePwntoolsMessage === 'function') return controller.handlePwntoolsMessage.bind(controller);
      if (typeof controller.handlePreviewMessage === 'function') return controller.handlePreviewMessage.bind(controller);
      return null;
    }

    /**
     * Dispatch a message to the first controller that handles it.
     * @param {HubMessage} message
     * @returns {boolean} true if a controller handled the message
     */
    function handleMessage(message) {
      for (const controller of controllers) {
        const handler = resolveHandler(controller);
        if (typeof handler !== 'function') continue;
        if (handler(message)) return true;
      }
      return false;
    }

    return {
      handleMessage,
      registerController,
    };
  }

  const api = { initMessageRouter };
  global.POFHubMessageRouter = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.messageRouter = api;
  }
})(window);
