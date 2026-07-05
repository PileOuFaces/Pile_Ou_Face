// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file pluginIframeRouter.js
 * @brief Bidirectional message router between the host webview and plugin iframes.
 *
 * Host→plugin:  dispatch(pluginId, msg) / broadcast(msg)
 * Plugin→host:  plugin iframes post {__pof_plugin:true, payload} messages that are
 *               forwarded to vscode.postMessage, or {__pof_call:true} PoF proxy calls
 *               that are resolved against window.PoF and replied to the source frame.
 */
(function () {
  'use strict';

  /** @type {any} vscode handle (provides postMessage to the extension host) */
  let _vscode = null;
  /** @type {any} window-like object owning PoF and addEventListener */
  let _win = null;
  /** @type {Map<string, any>} slug → iframe element */
  const _frames = new Map();
  /** @type {Map<string, Set<string>>} tabId → Set of plugin slugs that registered it */
  const _tabLoaders = new Map();
  /** @type {number} incremented on each init so stale listeners self-disable */
  let _generation = 0;

  /**
   * Initialize the router.
   * @param {Window} win   - Host window (or mock in tests)
   * @param {object} vscode - VS Code webview API object
   */
  function init(win, vscode) {
    // Remove previous listener if re-initializing (e.g. tests calling init multiple times)
    if (_win && typeof _win.removeEventListener === 'function') {
      _win.removeEventListener('message', _onMessage);
    }
    _frames.clear();
    _tabLoaders.clear();
    _generation++;
    _win = win;
    _vscode = vscode;
    const gen = _generation;
    win.addEventListener('message', function guardedListener(e) {
      // Discard events from stale registrations (router re-initialized)
      if (gen !== _generation) return;
      _onMessage(e);
    });
  }

  /**
   * Register an iframe element so the router can send messages to it.
   * @param {string} slug     - Plugin slug (e.g. "malware-triage-pro")
   * @param {HTMLIFrameElement} frameEl - The iframe DOM element
   */
  function register(slug, frameEl) {
    _frames.set(slug, frameEl);
  }

  /**
   * Dispatch a host-originated message to a specific plugin's iframe.
   * @param {string} pluginId - Plugin id (e.g. "pof.malware-triage-pro")
   * @param {object} msg
   */
  function dispatch(pluginId, msg) {
    for (const [, frame] of _frames) {
      if (frame.dataset.pluginId === pluginId) {
        frame.contentWindow.postMessage({ __pof_host: true, payload: msg }, '*');
        return;
      }
    }
  }

  /**
   * Broadcast a message to all registered plugin iframes.
   * @param {object} msg
   */
  function broadcast(msg) {
    for (const [, frame] of _frames) {
      frame.contentWindow.postMessage({ __pof_host: true, payload: msg }, '*');
    }
  }

  /** Send a PoF proxy reply back to a frame's contentWindow. */
  function _reply(contentWindow, seq, result) {
    contentWindow.postMessage({ __pof_host: true, payload: { __pof_reply: true, __seq: seq, result } }, '*');
  }

  /** Find the iframe element whose contentWindow matches the given window reference. */
  function _findFrame(sourceWindow) {
    for (const [, frame] of _frames) {
      if (frame.contentWindow === sourceWindow) return frame;
    }
    return null;
  }

  /** Handle an incoming message from any window. */
  async function _onMessage(e) {
    if (!e || !e.data || e.data.__pof_plugin !== true) return;

    const sourceWindow = e.source;
    const sourceFrame = _findFrame(sourceWindow);

    if (e.data.__pof_call) {
      // PoF proxy call: resolve method on window.PoF and reply
      const { method, args, __seq: seq } = e.data;
      const pof = (_win && _win.PoF) || (typeof window !== 'undefined' ? window.PoF : null);

      if (!pof || typeof pof[method] !== 'function') {
        if (sourceFrame) _reply(sourceFrame.contentWindow, seq, undefined);
        return;
      }

      // registerTabLoader: record the mapping, no async PoF call needed
      if (method === 'registerTabLoader') {
        const [tabId] = args;
        if (!_tabLoaders.has(tabId)) _tabLoaders.set(tabId, new Set());
        if (sourceFrame) _tabLoaders.get(tabId).add(sourceFrame.dataset.pluginSlug);
        if (sourceFrame) _reply(sourceFrame.contentWindow, seq, undefined);
        return;
      }

      try {
        const result = await Promise.resolve(pof[method](...(args || [])));
        if (sourceFrame) _reply(sourceFrame.contentWindow, seq, result);
      } catch (_) {
        if (sourceFrame) _reply(sourceFrame.contentWindow, seq, undefined);
      }
      return;
    }

    // Regular vscode.postMessage forward
    if (_vscode && e.data.payload != null) {
      _vscode.postMessage(e.data.payload);
    }
  }

  const PluginIframeRouter = { init, register, dispatch, broadcast };

  // CommonJS (Node / test environment) or browser global
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = PluginIframeRouter;
  } else if (typeof window !== 'undefined') {
    window.PluginIframeRouter = PluginIframeRouter;
  }
})();
