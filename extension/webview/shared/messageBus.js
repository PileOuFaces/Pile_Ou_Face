/**
 * VS Code message bridge for the hub webview.
 * Keeps a single acquireVsCodeApi() call and classic-script globals.
 */
(function initHubMessageBus(global) {
  const vscode = typeof acquireVsCodeApi === 'function'
    ? acquireVsCodeApi()
    : { postMessage() {} };
  const listeners = new Set();

  /**
   * Send a message to the VS Code extension.
   * @param {HubMessage} message
   */
  function postMessage(message) {
    vscode.postMessage(message);
  }

  /**
   * Subscribe to incoming messages from the extension.
   * @param {(event: MessageEvent<HubMessage>) => void} listener
   * @returns {() => void} Unsubscribe function
   */
  function onMessage(listener) {
    if (typeof listener !== 'function') return () => {};
    listeners.add(listener);
    return () => listeners.delete(listener);
  }

  global.addEventListener('message', (event) => {
    listeners.forEach((listener) => listener(event));
  });

  global.POFHubMessageBus = {
    vscode,
    postMessage,
    onMessage
  };
})(window);
