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

function loadPluginWebviews(root, options: { storageDir?: string; globalDir?: string; webviewResourceResolver?: (absPath: string) => string } = {}) {
  const { storageDir = '', globalDir = '', webviewResourceResolver } = options;
  let styles = '';
  let panels = '';
  let scripts = '';

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

      // CSS color for the group-tab
      const color = manifest?.ui?.tab_color;
      const family = String(manifest?.ui?.family || '').trim().replace(/[^a-zA-Z0-9_-]/g, '');
      const safeCss = (v) => (typeof v === 'string' && /^[a-zA-Z0-9#(),. %_-]+$/.test(v)) ? v : '';
      if (color && family) {
        styles += `\n.group-tab.active[data-group="${family}"] { background: ${safeCss(color.bg)}; color: ${safeCss(color.fg)}; border-color: ${safeCss(color.border)}; }`;
      }

      // Panel HTML
      const tabHtmlPath = webviewEntry.tab_html ? _resolvePluginAssetPath(pluginDir, manifest, webviewEntry.tab_html) : null;
      if (tabHtmlPath && fs.existsSync(tabHtmlPath)) {
        try {
          const pluginSlug = _derivePluginSlug(pluginDir, manifest);
          const rawHtml = fs.readFileSync(tabHtmlPath, 'utf8');
          const extracted = _extractInlineStyles(rawHtml);
          if (extracted.styles.trim()) styles += '\n' + _scopePluginCss(extracted.styles, pluginSlug);
          panels += '\n' + _markPluginPanels(extracted.html, pluginSlug, manifest.id || entry);
        } catch (_) { /* skip */ }
      }

      // Scripts
      const scriptPaths = Array.isArray(webviewEntry.scripts) ? webviewEntry.scripts : [];
      for (const rel of scriptPaths) {
        const scriptPath = _resolvePluginAssetPath(pluginDir, manifest, rel);
        if (!fs.existsSync(scriptPath)) continue;
        try {
          if (typeof webviewResourceResolver === 'function') {
            const scriptUri = String(webviewResourceResolver(scriptPath) || '').trim();
            if (scriptUri) {
              scripts += `\n<script src="${scriptUri}"></script>`;
            }
          } else {
            scripts += `\n<script>\n${fs.readFileSync(scriptPath, 'utf8')}\n</script>`;
          }
        } catch (_) { /* skip */ }
      }
    }
  }

  return { styles: styles.trim(), panels: panels.trim(), scripts: scripts.trim() };
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

  const { styles: pluginStyles, panels: pluginPanels, scripts: pluginScripts } =
    (storageDir || globalDir) ? loadPluginWebviews(workspaceRoot, {
      storageDir,
      globalDir,
    }) : { styles: '', panels: '', scripts: '' };

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
    .replace('{{pluginStyles}}', pluginStyles)
    .replace('{{pluginPanels}}', pluginPanels)
    .replace('{{pluginScripts}}', pluginScripts)
    .replace(/<body>/, `<body data-initial-panel="${initialPanel}">`);
}

module.exports = {
  getWebviewContent,
  getHubContent,
  loadPluginWebviews
};
