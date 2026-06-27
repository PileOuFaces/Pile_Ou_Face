/**
 * Shared state/storage helpers for the hub webview.
 * Loaded before hub.js and exposed on window for classic-script compatibility.
 */
(function initHubState(global) {
  const STORAGE_KEY = 'pile-ou-face-hub';

  /**
   * Load persisted hub state from localStorage.
   * @returns {Record<string, any>}
   */
  function loadStorage() {
    try {
      return JSON.parse(global.localStorage.getItem(STORAGE_KEY) || '{}') || {};
    } catch {
      return {};
    }
  }

  /**
   * Merge updates into persisted hub state and save.
   * @param {Record<string, any>} updates
   * @returns {Record<string, any>} The full saved state
   */
  function saveStorage(updates) {
    const current = loadStorage();
    const next = { ...current, ...(updates || {}) };
    global.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    return next;
  }

  global.POFHubState = {
    STORAGE_KEY,
    loadStorage,
    saveStorage
  };
})(window);
