// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file pluginIframeRouter.js
 * @brief Bidirectional message router between the host webview and plugin iframes.
 *
 * Host→plugin:  dispatch(pluginId, msg) / broadcast(msg)
 * Plugin→host:  plugin iframes post {__pof_plugin:true, payload} messages that are
 *               forwarded to vscode.postMessage, or {__pof_call:true} PoF proxy calls
 *               that are resolved against window.PoF and replied to the source frame.
 *
 * Plugin views are untrusted: they render analysed binaries. Only frames created
 * here may reach the host, each is limited to the capabilities listed below, and
 * the plugin identity always comes from the frame, never from the message.
 */
(function () {
  'use strict';

  /** Message types every plugin view may send, kept to what plugins really use. */
  const BASE_MESSAGE_TYPES = [
    'hubPluginInvoke',
    'hubError',
    'hubGoToAddress',
    'hubGoToFileOffset',
    'hubLoadDataXrefs',
    'hubLoadImportXrefs',
    'hubRevealStringAtAddress',
    // Sent by the bridge injected into every plugin frame (see webview.ts).
    'hubDebugLog',
    'hubLoadXrefs',
    'hubSaveFunctionReview',
  ];
  /** Extra message types, keyed by plugin id. */
  const PLUGIN_MESSAGE_TYPES = {
    'pof.malware-triage-pro': [
      'hubListRules',
      'hubGetRuleContent',
      'hubToggleRule',
      'hubAddUserRule',
      'hubUpdateUserRule',
      'hubDeleteUserRule',
      'hubBrowseImportRule',
      'requestRulesSelection',
    ],
    'pof.offensive-research-pro': ['hubPickFile'],
  };
  /** window.PoF methods reachable through the proxy. */
  const POF_METHODS = new Set([
    'getTabCache',
    'setTabCache',
    'registerTabLoader',
    'saveStorage',
    'navigateTo',
  ]);

  /**
   * Hub storage keys each plugin may write. The store also holds host settings
   * such as scriptCode and ollamaBaseUrl, so nothing else goes through.
   */
  const PLUGIN_STORAGE_KEYS = {
    'pof.cross-analysis-pro': [
      'crossAnalysisQuery',
      'crossAnalysisRisk',
      'crossAnalysisSource',
      'crossAnalysisMode',
      'crossAnalysisSort',
      'crossAnalysisCollapsedSections',
    ],
    'pof.malware-triage-pro': [
      'yaraRulesMode',
      'yaraRulesPath',
      'detectionCapaCollapsed',
      'detectionYaraCollapsed',
      'detectionRulesCollapsed',
    ],
    'pof.vulnerability-audit-pro': [
      'vulnKind',
      'vulnReview',
      'vulnCwe',
      'vulnContext',
      'vulnComparison',
      'vulnTriage',
      'vulnSort',
    ],
  };

  /** PoF methods whose first argument must be a tab of the calling plugin. */
  const TAB_SCOPED_METHODS = new Set(['getTabCache', 'setTabCache']);

  /** @type {any} vscode handle (provides postMessage to the extension host) */
  let _vscode = null;
  /** @type {any} window-like object owning PoF and addEventListener */
  let _win = null;
  /** @type {Map<string, any>} slug → iframe element */
  const _frames = new Map();
  /** @type {Map<string, Set<string>>} tabId → Set of plugin slugs that registered it */
  const _tabLoaders = new Map();
  /** @type {Function|null} currently registered message listener (for proper removal) */
  let _boundListener = null;
  /** @type {symbol} unique token identifying the current registration; stale closures self-disable */
  let _activeToken = Symbol();

  /**
   * Initialize the router.
   * @param {Window} win   - Host window (or mock in tests)
   * @param {object} vscode - VS Code webview API object
   */
  function init(win, vscode) {
    // Remove the previously registered listener, if any
    if (_win && _boundListener && typeof _win.removeEventListener === 'function') {
      _win.removeEventListener('message', _boundListener, true);
    }
    _frames.clear();
    _tabLoaders.clear();
    _win = win;
    _vscode = vscode;
    // Rotate the token so any stale closure registered on a window that does not
    // support removeEventListener (e.g. test mocks) will self-disable.
    _activeToken = Symbol();
    const token = _activeToken;
    _boundListener = function (e) {
      if (token !== _activeToken) return;
      if (!_isFromSandboxedFrame(e)) return;
      // Hub listeners treat every message as coming from the extension: a frame
      // writing straight to the parent must never reach them.
      if (typeof e.stopImmediatePropagation === 'function') e.stopImmediatePropagation();
      _onMessage(e);
    };
    // Capture runs before the hub's own listeners, whatever the script order.
    win.addEventListener('message', _boundListener, true);
  }

  /** The extension posts from the VS Code origin; sandboxed frames have an opaque one. */
  function _isFromSandboxedFrame(e) {
    if (!e) return false;
    return e.origin === 'null' || _findFrame(e.source) !== null;
  }

  /**
   * Register an iframe element so the router can send messages to it.
   * @param {string} slug     - Plugin slug (e.g. "analysis-demo")
   * @param {HTMLIFrameElement} frameEl - The iframe DOM element
   */
  function register(slug, frameEl) {
    _frames.set(slug, frameEl);
  }

  /** Remove a frame and everything it had registered. */
  function _removeFrame(slug) {
    const frame = _frames.get(slug);
    if (frame && typeof frame.remove === 'function') frame.remove();
    _frames.delete(slug);
    for (const slugs of _tabLoaders.values()) slugs.delete(slug);
  }

  /** Create the sandboxed iframe of an authorized plugin. */
  function _createFrame(spec, hostEl, onLoad) {
    const frame = hostEl.ownerDocument.createElement('iframe');
    frame.id = spec.frameId;
    frame.className = 'plugin-iframe static-panel';
    frame.dataset.pluginId = spec.pluginId;
    frame.dataset.pluginSlug = spec.pluginSlug;
    // Set before srcdoc: the frame must never load without its sandbox.
    frame.setAttribute('sandbox', 'allow-scripts');
    frame.setAttribute('srcdoc', spec.srcdoc);
    if (typeof onLoad === 'function') {
      frame.addEventListener('load', () => onLoad(frame));
    }
    hostEl.appendChild(frame);
    _frames.set(spec.pluginSlug, frame);
  }

  /**
   * Align live iframes with the plugins the extension currently authorizes.
   * Frames dropped from the list lose their script context immediately.
   * @param {{pluginId: string, pluginSlug: string, frameId: string, srcdoc: string}[]} specs
   * @param {HTMLElement} hostEl - Element receiving the iframes
   * @param {(frame: HTMLIFrameElement) => void} [onLoad]
   */
  function syncFrames(specs, hostEl, onLoad) {
    const wanted = new Map((Array.isArray(specs) ? specs : []).map((spec) => [spec.pluginSlug, spec]));
    for (const [slug, frame] of Array.from(_frames)) {
      const spec = wanted.get(slug);
      if (!spec || spec.pluginId !== frame.dataset.pluginId || spec.srcdoc !== frame.getAttribute('srcdoc')) {
        _removeFrame(slug);
      }
    }
    for (const [slug, spec] of wanted) {
      if (!_frames.has(slug)) _createFrame(spec, hostEl, onLoad);
    }
  }

  /**
   * Dispatch a host-originated message to a specific plugin's iframe.
   * @param {string} pluginId - Plugin id (e.g. "vendor.analysis-demo")
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

  /** Check whether a plugin iframe completed its tab-loader registration handshake. */
  function hasTabLoader(slug, tabId) {
    return _tabLoaders.get(String(tabId || ''))?.has(String(slug || '')) === true;
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

  /** Keep only the storage keys the calling plugin owns. */
  function _allowedStorageUpdates(frame, updates) {
    const pluginId = frame.dataset.pluginId;
    if (!updates || typeof updates !== 'object' || Array.isArray(updates)) return {};
    if (!Object.hasOwn(PLUGIN_STORAGE_KEYS, pluginId)) return {};
    const allowed = {};
    for (const key of PLUGIN_STORAGE_KEYS[pluginId]) {
      if (Object.hasOwn(updates, key)) allowed[key] = updates[key];
    }
    return allowed;
  }

  /** Check a message type against the capabilities of a plugin. */
  function _isAllowedMessage(pluginId, type) {
    return BASE_MESSAGE_TYPES.includes(type)
      || (Object.hasOwn(PLUGIN_MESSAGE_TYPES, pluginId) && PLUGIN_MESSAGE_TYPES[pluginId].includes(type));
  }

  /** Plugins only touch their own tabs: native tabs have no plugin owner. */
  function _ownsTab(frame, tabId) {
    if (typeof tabId !== 'string' || !tabId || typeof _win?.getPluginSlugForTab !== 'function') return false;
    return _win.getPluginSlugForTab(tabId) === frame.dataset.pluginSlug;
  }

  /** Record a plugin tab loader. */
  function _registerTabLoader(frame, pof, tabId) {
    const slug = frame.dataset.pluginSlug;
    if (!_ownsTab(frame, tabId)) return;
    if (!_tabLoaders.has(tabId)) _tabLoaders.set(tabId, new Set());
    _tabLoaders.get(tabId).add(slug);
    // Register a real callback in state.js so payload.js callTabLoader still fires
    pof.registerTabLoader(tabId, function (binaryPath) {
      const current = _frames.get(slug);
      if (!current) return;
      current.contentWindow.postMessage(
        { __pof_host: true, payload: { __pof_tabload: true, tabId, binaryPath } },
        '*'
      );
    });
  }

  /** Resolve a PoF proxy call for a registered frame. */
  async function _handlePofCall(frame, data) {
    const { method, args, __seq: seq } = data;
    const pof = (_win && _win.PoF) || (typeof window !== 'undefined' ? window.PoF : null);
    if (!POF_METHODS.has(method) || !pof || typeof pof[method] !== 'function') {
      _reply(frame.contentWindow, seq, undefined);
      return;
    }
    const firstArg = Array.isArray(args) ? args[0] : undefined;
    if (method === 'registerTabLoader') {
      _registerTabLoader(frame, pof, firstArg);
      _reply(frame.contentWindow, seq, undefined);
      return;
    }
    if (TAB_SCOPED_METHODS.has(method) && !_ownsTab(frame, firstArg)) {
      _reply(frame.contentWindow, seq, undefined);
      return;
    }
    try {
      const callArgs = method === 'saveStorage'
        ? [_allowedStorageUpdates(frame, firstArg)]
        : (Array.isArray(args) ? args : []);
      const result = await Promise.resolve(pof[method](...callArgs));
      _reply(frame.contentWindow, seq, result);
    } catch (_) {
      _reply(frame.contentWindow, seq, undefined);
    }
  }

  /** Handle a message posted by a sandboxed frame. */
  async function _onMessage(e) {
    try {
      const frame = _findFrame(e.source);
      if (!frame || !e.data || e.data.__pof_plugin !== true) return;

      if (e.data.__pof_call) {
        await _handlePofCall(frame, e.data);
        return;
      }

      const payload = e.data.payload;
      if (!_vscode || !payload || !_isAllowedMessage(frame.dataset.pluginId, payload.type)) return;
      _vscode.postMessage({ ...payload, __pofPluginId: frame.dataset.pluginId });
    } catch (_err) {
      // swallow — plugin messages must never crash the host
    }
  }

  const PluginIframeRouter = { init, register, syncFrames, dispatch, broadcast, hasTabLoader };

  // CommonJS (Node / test environment) or browser global
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = PluginIframeRouter;
  } else if (typeof window !== 'undefined') {
    window.PluginIframeRouter = PluginIframeRouter;
  }
})();
