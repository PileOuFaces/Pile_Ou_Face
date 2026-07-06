// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file webview.js
 * @brief Construction du HTML des webviews.
 */

const vscode = require('vscode');
const fs = require('fs');
const path = require('path');

function _readJsonIfExists(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (_) {
    return null;
  }
}

function _derivePluginSlug(pluginDir, manifest) {
  const buildMeta = _readJsonIfExists(path.join(pluginDir, 'metadata', 'build.json'));
  const slugFromBuild = String(buildMeta?.slug || '').trim();
  if (slugFromBuild) return slugFromBuild;
  const pluginId = String(manifest?.id || '').trim();
  if (pluginId.startsWith('pof.')) return pluginId.slice(4);
  return path.basename(pluginDir);
}

function _resolvePluginAssetPath(pluginDir, manifest, relativeAssetPath) {
  const relPath = String(relativeAssetPath || '').trim();
  if (!relPath) return '';
  const directPath = path.join(pluginDir, relPath);
  if (fs.existsSync(directPath)) return directPath;
  const slug = _derivePluginSlug(pluginDir, manifest);
  const extrasPath = path.join(pluginDir, 'metadata', 'extras', 'plugins', slug, relPath);
  if (fs.existsSync(extrasPath)) return extrasPath;
  return '';
}

function _escapeHtmlAttr(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function _extractInlineStyles(html) {
  let styles = '';
  const withoutStyles = String(html || '').replace(/<style\b[^>]*>([\s\S]*?)<\/style>/gi, (_match, css) => {
    styles += `\n${css || ''}`;
    return '';
  });
  return { html: withoutStyles, styles };
}

function _scopeCssSelector(selector, scope) {
  const trimmed = String(selector || '').trim();
  if (!trimmed) return '';
  if (trimmed.startsWith('@')) return trimmed;
  if (/^[>+~]/.test(trimmed)) return `${scope} ${trimmed}`;
  if (/^[.#[:]/.test(trimmed)) return `:where(${scope}, ${scope} *)${trimmed}`;
  return `${scope} ${trimmed}`;
}

function _scopePluginCss(css, pluginSlug) {
  const scope = `[data-plugin-scope="${String(pluginSlug || '').replace(/[^a-zA-Z0-9_-]/g, '')}"]`;
  const source = String(css || '');
  let result = '';
  let index = 0;

  while (index < source.length) {
    const open = source.indexOf('{', index);
    if (open === -1) {
      result += source.slice(index);
      break;
    }
    const selectorText = source.slice(index, open);
    let depth = 1;
    let cursor = open + 1;
    while (cursor < source.length && depth > 0) {
      const ch = source[cursor];
      if (ch === '{') depth += 1;
      else if (ch === '}') depth -= 1;
      cursor += 1;
    }
    const body = source.slice(open + 1, cursor - 1);
    const selector = selectorText.trim();

    if (!selector) {
      result += source.slice(index, cursor);
    } else if (/^@(keyframes|font-face)\b/i.test(selector)) {
      result += `${selectorText}{${body}}`;
    } else if (/^@(media|supports|container)\b/i.test(selector)) {
      result += `${selectorText}{${_scopePluginCss(body, pluginSlug)}}`;
    } else {
      const scoped = selector
        .split(',')
        .map((item) => _scopeCssSelector(item, scope))
        .filter(Boolean)
        .join(', ');
      result += scoped ? `${scoped} {${body}}` : `${selectorText}{${body}}`;
    }
    index = cursor;
  }

  return result;
}

function _markPluginPanels(html, pluginSlug, pluginId) {
  const safeSlug = _escapeHtmlAttr(String(pluginSlug || '').replace(/[^a-zA-Z0-9_-]/g, ''));
  const safeId = _escapeHtmlAttr(pluginId || '');
  return String(html || '').replace(/<([a-z][\w:-]*)([^>]*\bclass=(["'])[^"']*\bstatic-panel\b[^"']*\3[^>]*)>/gi, (match, tag, attrs) => {
    if (/\bdata-plugin-scope=/.test(attrs)) return match;
    return `<${tag}${attrs} data-plugin-scope="${safeSlug}" data-plugin-id="${safeId}">`;
  });
}

function _getPluginSearchDirs(storageDir, _globalDir) {
  const dirs: string[] = [];
  if (storageDir) dirs.push(path.join(storageDir, 'plugins'));
  return dirs;
}

const PLUGIN_BRIDGE_PREAMBLE = `<script>
(function () {
  var _pending = {};
  var _seq = 0;
  window.vscode = {
    postMessage: function (msg) { window.parent.postMessage({ __pof_plugin: true, payload: msg }, '*'); }
  };
  window.addEventListener('message', function (e) {
    if (!e.data || !e.data.__pof_host) return;
    var msg = e.data.payload;
    if (msg && msg.__pof_reply && _pending[msg.__seq]) {
      _pending[msg.__seq](msg.result);
      delete _pending[msg.__seq];
    }
    if (msg && msg.type === 'showTab') {
      var tabId = String(msg.tabId || '');
      var panelId = 'static' + tabId.split('_').map(function (w) { return w.charAt(0).toUpperCase() + w.slice(1); }).join('');
      document.querySelectorAll('.static-panel').forEach(function (p) { p.classList.remove('active'); });
      var panel = document.getElementById(panelId);
      if (panel) panel.classList.add('active');
    }
  });
  function _call(method, args) {
    return new Promise(function (resolve) {
      var seq = ++_seq;
      _pending[seq] = resolve;
      window.parent.postMessage({ __pof_plugin: true, __pof_call: true, method: method, args: args, __seq: seq }, '*');
    });
  }
  window.PoF = {
    version: null,
    getBinaryPath:       function () { return _call('getBinaryPath', []); },
    getTabCache:         function (k) { return _call('getTabCache', [k]); },
    setTabCache:         function (k, v) { return _call('setTabCache', [k, v]); },
    registerTabLoader:   function (tabId, fn) {
      _call('registerTabLoader', [tabId]);
      window.addEventListener('message', function (e) {
        if (e.data && e.data.__pof_host && e.data.payload && e.data.payload.__pof_tabload && e.data.payload.tabId === tabId) {
          if (e.data.payload.binaryPath) window._pofCurrentBinaryPath = e.data.payload.binaryPath;
          fn(e.data.payload.binaryPath);
        }
      });
    },
    setYaraResults:      function (m, err) { return _call('setYaraResults', [m, err]); },
    setCapaResults:      function (c, err) { return _call('setCapaResults', [c, err]); },
    setDetectionMeta:    function (d) { return _call('setDetectionMeta', [d]); },
    getDetectionState:   function () { return _call('getDetectionState', []); },
    clearDetectionState: function () { return _call('clearDetectionState', []); },
    setLoading:          function (id, msg) { return _call('setLoading', [id, msg]); },
    renderRulesList:     function (id, rules) { return _call('renderRulesList', [id, rules]); },
    applyYaraModeUi:     function () { return _call('applyYaraModeUi', []); },
    getYaraMode:         function () { return _call('getYaraMode', []); },
    setYaraMode:         function (mode, opts) { return _call('setYaraMode', [mode, opts]); },
    saveStorage:         function (d) { return _call('saveStorage', [d]); },
  };
  // Stubs for host-page globals called by legacy plugin code (before window.PoF migration)
  window._pofCurrentBinaryPath = '';
  window._pofSavedState = {};
  window.getStaticBinaryPath = function () { return window._pofCurrentBinaryPath; };
  window._loadStorage = function () { return window._pofSavedState; };
  window._saveStorage = function (data) {
    if (data && typeof data === 'object') Object.assign(window._pofSavedState, data);
  };
})();
</script>`;

function _buildPluginSrcdoc(html, inlineJs, scopedCss) {
  const safeCss = String(scopedCss || '').replace(/<\/style/gi, '<\\/style');
  const styleBlock = safeCss ? `<style>${safeCss}</style>` : '';
  const safeJs = String(inlineJs || '').replace(/<\/script/gi, '<\\/script');
  const scriptBlock = safeJs ? `<script>${safeJs}</script>` : '';
  return [
    '<!DOCTYPE html><html><head>',
    '<meta charset="utf-8">',
    '<style>*{box-sizing:border-box;margin:0}body{overflow:hidden}.static-panel{display:none;flex-direction:column;height:100%}.static-panel.active{display:flex}</style>',
    styleBlock,
    PLUGIN_BRIDGE_PREAMBLE,
    '</head><body>',
    String(html || ''),
    scriptBlock,
    '</body></html>',
  ].join('');
}

function loadPluginWebviews(root, options: { storageDir?: string; globalDir?: string; webviewResourceResolver?: (absPath: string) => string } = {}) {
  const { storageDir = '', globalDir = '', webviewResourceResolver } = options;
  let groupStyles = '';
  const frames: { pluginId: string; pluginSlug: string; frameId: string; srcdoc: string }[] = [];

  const searchDirs = _getPluginSearchDirs(storageDir, globalDir);

  for (const pluginsDir of searchDirs) {
    if (!fs.existsSync(pluginsDir)) continue;

    let entries;
    try { entries = fs.readdirSync(pluginsDir); } catch (_) { continue; }

    for (const entry of entries) {
      const pluginDir = path.join(pluginsDir, entry);
      const manifestPath = fs.existsSync(path.join(pluginDir, 'plugin.json'))
        ? path.join(pluginDir, 'plugin.json')
        : path.join(pluginDir, 'manifest.json');
      const manifest = _readJsonIfExists(manifestPath);
      if (!manifest) continue;

      const webviewEntry = manifest?.entrypoints?.webview;
      if (!webviewEntry) continue;

      // CSS color for the group-tab (goes into host page, not srcdoc)
      const color = manifest?.ui?.tab_color;
      const family = String(manifest?.ui?.family || '').trim().replace(/[^a-zA-Z0-9_-]/g, '');
      const safeCss = (v) => (typeof v === 'string' && /^[a-zA-Z0-9#(),. %_-]+$/.test(v)) ? v : '';
      if (color && family) {
        groupStyles += `\n.group-tab.active[data-group="${family}"] { background: ${safeCss(color.bg)}; color: ${safeCss(color.fg)}; border-color: ${safeCss(color.border)}; }`;
      }

      // Build srcdoc
      const pluginSlug = _derivePluginSlug(pluginDir, manifest);
      const pluginId = manifest.id || entry;

      const tabHtmlPath = webviewEntry.tab_html ? _resolvePluginAssetPath(pluginDir, manifest, webviewEntry.tab_html) : null;
      let pluginHtml = '';
      let scopedCss = '';

      if (tabHtmlPath && fs.existsSync(tabHtmlPath)) {
        try {
          const rawHtml = fs.readFileSync(tabHtmlPath, 'utf8');
          const extracted = _extractInlineStyles(rawHtml);
          if (extracted.styles.trim()) scopedCss = _scopePluginCss(extracted.styles, pluginSlug);
          pluginHtml = _markPluginPanels(extracted.html, pluginSlug, pluginId);
        } catch (_) { /* skip */ }
      }

      // Collect inline JS content (always read file content for srcdoc — external URIs won't work)
      let inlineJs = '';
      const scriptPaths = Array.isArray(webviewEntry.scripts) ? webviewEntry.scripts : [];
      for (const rel of scriptPaths) {
        const scriptPath = _resolvePluginAssetPath(pluginDir, manifest, rel);
        if (!fs.existsSync(scriptPath)) continue;
        try {
          inlineJs += `\n${fs.readFileSync(scriptPath, 'utf8')}`;
        } catch (_) { /* skip */ }
      }

      // Only push a frame if there is actual webview content
      if (!pluginHtml.trim() && !inlineJs.trim() && !scopedCss.trim()) continue;

      const srcdoc = _buildPluginSrcdoc(pluginHtml, inlineJs, scopedCss);
      const frameId = `pof-plugin-frame-${pluginSlug}`;
      frames.push({ pluginId, pluginSlug, frameId, srcdoc });
    }
  }

  const framesHtml = frames.map((f) => {
    const escapedSrcdoc = _escapeHtmlAttr(f.srcdoc);
    return `<iframe id="${f.frameId}" data-plugin-id="${_escapeHtmlAttr(f.pluginId)}" data-plugin-slug="${_escapeHtmlAttr(f.pluginSlug)}" class="plugin-iframe static-panel" sandbox="allow-scripts" srcdoc="${escapedSrcdoc}"></iframe>`;
  }).join('\n');

  return { groupStyles: groupStyles.trim(), frames, framesHtml: framesHtml.trim() };
}

function getWebviewContent(webview, extensionUri) {
  const preferredPath = vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'graphical-stack.html');
  const legacyPath = vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'visualizer.html');
  let html = '';
  if (fs.existsSync(preferredPath.fsPath)) {
    html = fs.readFileSync(preferredPath.fsPath, 'utf8');
  } else {
    html = fs.readFileSync(legacyPath.fsPath, 'utf8');
  }
  const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'app', 'main.js'));
  const preferredStyle = vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'graphical-stack.css');
  const fallbackStyle = vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'legacy-visualizer.css');
  const stylePath = fs.existsSync(preferredStyle.fsPath) ? preferredStyle : fallbackStyle;
  const styleUri = webview.asWebviewUri(stylePath);
  const csp = webview.cspSource;
  return html
    .replace(/{{scriptUri}}/g, scriptUri.toString())
    .replace(/{{styleUri}}/g, styleUri.toString())
    .replace(/{{cspSource}}/g, csp);
}

// static/hub — main static analysis hub (shell + fragments)
function getHubContent(webview, extensionUri, initialPanel = 'dashboard', workspaceRoot = '', globalDir = '', storageDir = '') {
  const read = (...parts) => fs.readFileSync(
    vscode.Uri.joinPath(extensionUri, ...parts).fsPath, 'utf8'
  );

  const { groupStyles: pluginGroupStyles, framesHtml: pluginFrames } =
    (storageDir || globalDir) ? loadPluginWebviews(workspaceRoot, {
      storageDir,
      globalDir,
    }) : { groupStyles: '', framesHtml: '' };

  const html = read('front', 'hub.html')
    .replace('{{panelDashboard}}', read('front', 'shared', 'panel-dashboard.html'))
    .replace('{{panelStatic}}',    read('front', 'static',  'panel-static.html'))
    .replace('{{panelDynamic}}',   read('front', 'dynamic', 'panel-dynamic.html'))
    .replace('{{panelOutils}}',    read('front', 'shared',  'panel-outils.html'))
    .replace('{{panelOptions}}',   read('front', 'shared',  'panel-options.html'));

  const scriptUri              = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'hub.js'));
  // shared modules
  const sharedRawTabCapabilitiesUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'rawTabCapabilities.js'));
  const sharedStateUri         = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'state.js'));
  const sharedBinaryUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'binary.js'));
  const sharedNavUri           = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'nav.js'));
  const sharedMarkdownRendererUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'markdownRenderer.js'));
  const sharedChatMessageActionsUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'chatMessageActions.js'));
  const sharedChatExportUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'chatExport.js'));
  const sharedChatHistoryUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'chatHistory.js'));
  const sharedChatContextBudgetUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'chatContextBudget.js'));
  const sharedAiGenerationSettingsUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'aiGenerationSettings.js'));
  const sharedAiPricingUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'aiPricing.js'));
  const sharedAiContextActionsUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'aiContextActions.js'));
  const sharedOutilsUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'outils.js'));
  const sharedMessagesUri      = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'messages.js'));
  const sharedSettingsUri      = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'settings.js'));
  const sharedAnnotationsUri   = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'annotations.js'));
  const sharedAccountUri       = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'account.js'));
  // static modules
  const staticPayloadUri       = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'payload.js'));
  const staticSearchUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'search.js'));
  const staticToolsUri         = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'tools.js'));
  const staticDiffUri          = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'diff.js'));
  // dynamic modules
  const dynamicPanelUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'panel.js'));
  // shared controllers
  const sharedHubStateUri              = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'hubState.js'));
  const sharedMessageBusUri            = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'messageBus.js'));
  const sharedTaskProgressControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'taskProgressController.js'));
  const sharedMessageRouterUri         = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'messageRouter.js'));
  const sharedStatusControllerUri      = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'statusController.js'));
  const sharedToastControllerUri       = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'toastController.js'));
  const sharedArchBadgeControllerUri   = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'archBadgeController.js'));
  const sharedBinarySourceControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'binarySourceController.js'));
  const sharedExploitNotesControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'exploitNotesController.js'));
  const sharedHubIndexUri              = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'hubIndex.js'));
  const sharedConversionControllerUri  = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'conversionController.js'));
  // static controllers
  const staticPayloadCoreUri           = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'payloadCore.js'));
  const staticPayloadTabsControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'payloadTabsController.js'));
  const staticPayloadBuilderControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'payloadBuilderController.js'));
  const staticPayloadStateControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'payloadStateController.js'));
  const staticPayloadPreviewControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'payloadPreviewController.js'));
  const staticFilePayloadControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'filePayloadController.js'));
  const staticExploitHelperControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'exploitHelperController.js'));
  const staticPwntoolsScriptControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'pwntoolsScriptController.js'));
  const staticToolsWidgetsControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'staticToolsWidgetsController.js'));
  // dynamic controllers
  const dynamicPayloadHistoryControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'payloadHistoryController.js'));
  const dynamicVisualizerControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'dynamicVisualizerController.js'));
  const dynamicPresetControllerUri     = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'dynamicPresetController.js'));
  const dynamicRunTraceControllerUri   = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'runTraceController.js'));
  const dynamicRuntimeFallbackRendererUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'runtimeFallbackRenderer.js'));
  const dynamicRuntimeSessionControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'runtimeSessionController.js'));
  const dynamicRuntimeWorkspaceLayoutControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'runtimeWorkspaceLayoutController.js'));
  const dynamicPayloadUri              = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'dynamicPayload.js'));
  // shared helpers
  const cfgHelpersUri          = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'cfgHelpers.js'));
  const exploitHelperUri       = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'exploitHelper.js'));
  const payloadPreviewUri      = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'payloadPreview.js'));
  const sharedConversionUtilsUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'conversionUtils.js'));
  const elkUri                 = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'elk.bundled.js'));
  // CSS
  const baseCssUri             = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'base.css'));
  const dashboardCssUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'panel-dashboard.css'));
  const staticBinaryBarCssUri  = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'binary-bar.css'));
  const staticDisasmCssUri     = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'disasm.css'));
  const staticCfgCssUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'cfg.css'));
  const staticDecompileCssUri  = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'decompile.css'));
  const staticSearchCssUri     = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'search.css'));
  const staticAnalysisCssUri   = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'analysis.css'));
  const staticToolsCssUri      = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'tools.css'));
  const dynamicCssUri          = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'panel-dynamic.css'));
  const dynamicRuntimeSessionCssUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'runtime-session.css'));
  const graphicalStackHubCssUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'graphical-stack-hub.css'));
  const dynamicRuntimeLayoutCssUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'runtime-layout.css'));
  const runtimeModuleUri       = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'app', 'main.js'));
  const outilsCssUri           = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'panel-outils.css'));
  const optionsCssUri          = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'panel-options.css'));
  const pluginIframeRouterUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'pluginIframeRouter.js'));
  const csp = webview.cspSource;

  return html
    .replace(/{{scriptUri}}/g, scriptUri.toString())
    // shared modules
    .replace(/{{sharedRawTabCapabilitiesUri}}/g, sharedRawTabCapabilitiesUri.toString())
    .replace(/{{sharedStateUri}}/g, sharedStateUri.toString())
    .replace(/{{sharedBinaryUri}}/g, sharedBinaryUri.toString())
    .replace(/{{sharedNavUri}}/g, sharedNavUri.toString())
    .replace(/{{sharedMarkdownRendererUri}}/g, sharedMarkdownRendererUri.toString())
    .replace(/{{sharedChatMessageActionsUri}}/g, sharedChatMessageActionsUri.toString())
    .replace(/{{sharedChatExportUri}}/g, sharedChatExportUri.toString())
    .replace(/{{sharedChatHistoryUri}}/g, sharedChatHistoryUri.toString())
    .replace(/{{sharedChatContextBudgetUri}}/g, sharedChatContextBudgetUri.toString())
    .replace(/{{sharedAiGenerationSettingsUri}}/g, sharedAiGenerationSettingsUri.toString())
    .replace(/{{sharedAiPricingUri}}/g, sharedAiPricingUri.toString())
    .replace(/{{sharedAiContextActionsUri}}/g, sharedAiContextActionsUri.toString())
    .replace(/{{sharedOutilsUri}}/g, sharedOutilsUri.toString())
    .replace(/{{sharedMessagesUri}}/g, sharedMessagesUri.toString())
    .replace(/{{sharedSettingsUri}}/g, sharedSettingsUri.toString())
    .replace(/{{sharedAnnotationsUri}}/g, sharedAnnotationsUri.toString())
    .replace(/{{sharedAccountUri}}/g, sharedAccountUri.toString())
    // static modules
    .replace(/{{staticPayloadUri}}/g, staticPayloadUri.toString())
    .replace(/{{staticSearchUri}}/g, staticSearchUri.toString())
    .replace(/{{staticToolsUri}}/g, staticToolsUri.toString())
    .replace(/{{staticDiffUri}}/g, staticDiffUri.toString())
    // dynamic modules
    .replace(/{{dynamicPanelUri}}/g, dynamicPanelUri.toString())
    // shared controllers
    .replace(/{{sharedHubStateUri}}/g, sharedHubStateUri.toString())
    .replace(/{{sharedMessageBusUri}}/g, sharedMessageBusUri.toString())
    .replace(/{{sharedTaskProgressControllerUri}}/g, sharedTaskProgressControllerUri.toString())
    .replace(/{{sharedMessageRouterUri}}/g, sharedMessageRouterUri.toString())
    .replace(/{{sharedStatusControllerUri}}/g, sharedStatusControllerUri.toString())
    .replace(/{{sharedToastControllerUri}}/g, sharedToastControllerUri.toString())
    .replace(/{{sharedArchBadgeControllerUri}}/g, sharedArchBadgeControllerUri.toString())
    .replace(/{{sharedBinarySourceControllerUri}}/g, sharedBinarySourceControllerUri.toString())
    .replace(/{{sharedExploitNotesControllerUri}}/g, sharedExploitNotesControllerUri.toString())
    .replace(/{{sharedHubIndexUri}}/g, sharedHubIndexUri.toString())
    .replace(/{{sharedConversionControllerUri}}/g, sharedConversionControllerUri.toString())
    // static controllers
    .replace(/{{staticPayloadCoreUri}}/g, staticPayloadCoreUri.toString())
    .replace(/{{staticPayloadTabsControllerUri}}/g, staticPayloadTabsControllerUri.toString())
    .replace(/{{staticPayloadBuilderControllerUri}}/g, staticPayloadBuilderControllerUri.toString())
    .replace(/{{staticPayloadStateControllerUri}}/g, staticPayloadStateControllerUri.toString())
    .replace(/{{staticPayloadPreviewControllerUri}}/g, staticPayloadPreviewControllerUri.toString())
    .replace(/{{staticFilePayloadControllerUri}}/g, staticFilePayloadControllerUri.toString())
    .replace(/{{staticExploitHelperControllerUri}}/g, staticExploitHelperControllerUri.toString())
    .replace(/{{staticPwntoolsScriptControllerUri}}/g, staticPwntoolsScriptControllerUri.toString())
    .replace(/{{staticToolsWidgetsControllerUri}}/g, staticToolsWidgetsControllerUri.toString())
    // dynamic controllers
    .replace(/{{dynamicPayloadHistoryControllerUri}}/g, dynamicPayloadHistoryControllerUri.toString())
    .replace(/{{dynamicVisualizerControllerUri}}/g, dynamicVisualizerControllerUri.toString())
    .replace(/{{dynamicPresetControllerUri}}/g, dynamicPresetControllerUri.toString())
    .replace(/{{dynamicRunTraceControllerUri}}/g, dynamicRunTraceControllerUri.toString())
    .replace(/{{dynamicRuntimeFallbackRendererUri}}/g, dynamicRuntimeFallbackRendererUri.toString())
    .replace(/{{dynamicRuntimeSessionControllerUri}}/g, dynamicRuntimeSessionControllerUri.toString())
    .replace(/{{dynamicRuntimeWorkspaceLayoutControllerUri}}/g, dynamicRuntimeWorkspaceLayoutControllerUri.toString())
    .replace(/{{dynamicPayloadUri}}/g, dynamicPayloadUri.toString())
    // shared helpers
    .replace(/{{cfgHelpersUri}}/g, cfgHelpersUri.toString())
    .replace(/{{exploitHelperUri}}/g, exploitHelperUri.toString())
    .replace(/{{payloadPreviewUri}}/g, payloadPreviewUri.toString())
    .replace(/{{sharedConversionUtilsUri}}/g, sharedConversionUtilsUri.toString())
    .replace(/{{elkUri}}/g, elkUri.toString())
    // CSS
    .replace(/{{baseCssUri}}/g, baseCssUri.toString())
    .replace(/{{dashboardCssUri}}/g, dashboardCssUri.toString())
    .replace(/{{staticBinaryBarCssUri}}/g, staticBinaryBarCssUri.toString())
    .replace(/{{staticDisasmCssUri}}/g, staticDisasmCssUri.toString())
    .replace(/{{staticCfgCssUri}}/g, staticCfgCssUri.toString())
    .replace(/{{staticDecompileCssUri}}/g, staticDecompileCssUri.toString())
    .replace(/{{staticSearchCssUri}}/g, staticSearchCssUri.toString())
    .replace(/{{staticAnalysisCssUri}}/g, staticAnalysisCssUri.toString())
    .replace(/{{staticToolsCssUri}}/g, staticToolsCssUri.toString())
    .replace(/{{dynamicCssUri}}/g, dynamicCssUri.toString())
    .replace(/{{dynamicRuntimeSessionCssUri}}/g, dynamicRuntimeSessionCssUri.toString())
    .replace(/{{graphicalStackHubCssUri}}/g, graphicalStackHubCssUri.toString())
    .replace(/{{dynamicRuntimeLayoutCssUri}}/g, dynamicRuntimeLayoutCssUri.toString())
    .replace(/{{runtimeModuleUri}}/g, runtimeModuleUri.toString())
    .replace(/{{outilsCssUri}}/g, outilsCssUri.toString())
    .replace(/{{optionsCssUri}}/g, optionsCssUri.toString())
    .replace(/{{cspSource}}/g, csp)
    .replace('{{pluginGroupStyles}}', pluginGroupStyles)
    .replace('{{pluginFrames}}', pluginFrames)
    .replace(/{{pluginIframeRouterUri}}/g, pluginIframeRouterUri.toString())
    .replace(/<body>/, `<body data-initial-panel="${initialPanel}">`);
}

module.exports = {
  getWebviewContent,
  getHubContent,
  loadPluginWebviews
};
