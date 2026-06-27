// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file webview.js
 * @brief Construction du HTML des webviews.
 */

const vscode = require('vscode');
const fs = require('fs');
const os = require('os');
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

function _getPluginSearchDirs(root, includeUserPlugins = false) {
  const workspacePluginsDir = path.join(root, '.pile-ou-face', 'plugins');
  if (!includeUserPlugins) return [workspacePluginsDir];
  const homePluginsDir = path.join(os.homedir(), '.pile-ou-face', 'plugins');
  return [...new Set([workspacePluginsDir, homePluginsDir])];
}

function loadPluginWebviews(root, options: { includeUserPlugins?: boolean; webviewResourceResolver?: (absPath: string) => string } = {}) {
  const { includeUserPlugins = false, webviewResourceResolver } = options;
  let styles = '';
  let panels = '';
  let scripts = '';

  for (const pluginsDir of _getPluginSearchDirs(root, includeUserPlugins)) {
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
        try { panels += '\n' + fs.readFileSync(tabHtmlPath, 'utf8'); } catch (_) { /* skip */ }
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
  const preferredPath = vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'graphical-stack.html');
  const legacyPath = vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'visualizer.html');
  let html = '';
  if (fs.existsSync(preferredPath.fsPath)) {
    html = fs.readFileSync(preferredPath.fsPath, 'utf8');
  } else {
    html = fs.readFileSync(legacyPath.fsPath, 'utf8');
  }
  const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'app', 'main.js'));
  const preferredStyle = vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'graphical-stack.css');
  const fallbackStyle = vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'legacy-visualizer.css');
  const stylePath = fs.existsSync(preferredStyle.fsPath) ? preferredStyle : fallbackStyle;
  const styleUri = webview.asWebviewUri(stylePath);
  const csp = webview.cspSource;
  return html
    .replace(/{{scriptUri}}/g, scriptUri.toString())
    .replace(/{{styleUri}}/g, styleUri.toString())
    .replace(/{{cspSource}}/g, csp);
}

// static/hub — main static analysis hub (shell + fragments)
function getHubContent(webview, extensionUri, initialPanel = 'dashboard', workspaceRoot = '') {
  const read = (...parts) => fs.readFileSync(
    vscode.Uri.joinPath(extensionUri, ...parts).fsPath, 'utf8'
  );

  const { styles: pluginStyles, panels: pluginPanels, scripts: pluginScripts } =
    workspaceRoot ? loadPluginWebviews(workspaceRoot, {
      includeUserPlugins: true,
      webviewResourceResolver: (filePath) => webview.asWebviewUri(vscode.Uri.file(filePath)).toString(),
    }) : { styles: '', panels: '', scripts: '' };

  const html = read('webview', 'hub.html')
    .replace('{{panelDashboard}}', read('webview', 'shared', 'panel-dashboard.html'))
    .replace('{{panelStatic}}',    read('webview', 'static',  'panel-static.html'))
    .replace('{{panelDynamic}}',   read('webview', 'dynamic', 'panel-dynamic.html'))
    .replace('{{panelOutils}}',    read('webview', 'shared',  'panel-outils.html'))
    .replace('{{panelOptions}}',   read('webview', 'shared',  'panel-options.html'));

  const scriptUri              = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'hub.js'));
  // shared modules
  const sharedStateUri         = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'state.js'));
  const sharedBinaryUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'binary.js'));
  const sharedNavUri           = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'nav.js'));
  const sharedMarkdownRendererUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'markdownRenderer.js'));
  const sharedChatMessageActionsUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'chatMessageActions.js'));
  const sharedChatExportUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'chatExport.js'));
  const sharedChatHistoryUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'chatHistory.js'));
  const sharedChatContextBudgetUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'chatContextBudget.js'));
  const sharedAiGenerationSettingsUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'aiGenerationSettings.js'));
  const sharedAiPricingUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'aiPricing.js'));
  const sharedAiContextActionsUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'aiContextActions.js'));
  const sharedOutilsUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'outils.js'));
  const sharedMessagesUri      = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'messages.js'));
  const sharedSettingsUri      = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'settings.js'));
  const sharedAnnotationsUri   = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'annotations.js'));
  const sharedAccountUri       = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'account.js'));
  // static modules
  const staticPayloadUri       = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'payload.js'));
  const staticSearchUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'search.js'));
  const staticToolsUri         = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'tools.js'));
  const staticDiffUri          = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'diff.js'));
  // dynamic modules
  const dynamicPanelUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'panel.js'));
  // shared controllers
  const sharedHubStateUri              = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'hubState.js'));
  const sharedMessageBusUri            = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'messageBus.js'));
  const sharedMessageRouterUri         = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'messageRouter.js'));
  const sharedStatusControllerUri      = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'statusController.js'));
  const sharedToastControllerUri       = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'toastController.js'));
  const sharedArchBadgeControllerUri   = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'archBadgeController.js'));
  const sharedBinarySourceControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'binarySourceController.js'));
  const sharedExploitNotesControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'exploitNotesController.js'));
  const sharedHubIndexUri              = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'hubIndex.js'));
  const sharedConversionControllerUri  = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'conversionController.js'));
  // static controllers
  const staticPayloadCoreUri           = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'payloadCore.js'));
  const staticPayloadTabsControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'payloadTabsController.js'));
  const staticPayloadBuilderControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'payloadBuilderController.js'));
  const staticPayloadStateControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'payloadStateController.js'));
  const staticPayloadPreviewControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'payloadPreviewController.js'));
  const staticFilePayloadControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'filePayloadController.js'));
  const staticExploitHelperControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'exploitHelperController.js'));
  const staticPwntoolsScriptControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'pwntoolsScriptController.js'));
  const staticToolsWidgetsControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'staticToolsWidgetsController.js'));
  // dynamic controllers
  const dynamicPayloadHistoryControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'payloadHistoryController.js'));
  const dynamicVisualizerControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'dynamicVisualizerController.js'));
  const dynamicPresetControllerUri     = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'dynamicPresetController.js'));
  const dynamicRunTraceControllerUri   = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'runTraceController.js'));
  const dynamicRuntimeFallbackRendererUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'runtimeFallbackRenderer.js'));
  const dynamicRuntimeSessionControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'runtimeSessionController.js'));
  const dynamicRuntimeWorkspaceLayoutControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'runtimeWorkspaceLayoutController.js'));
  const dynamicPayloadUri              = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'dynamicPayload.js'));
  // shared helpers
  const cfgHelpersUri          = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'cfgHelpers.js'));
  const exploitHelperUri       = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'exploitHelper.js'));
  const payloadPreviewUri      = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'payloadPreview.js'));
  const sharedConversionUtilsUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'conversionUtils.js'));
  const elkUri                 = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'elk.bundled.js'));
  // CSS
  const baseCssUri             = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'base.css'));
  const dashboardCssUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'panel-dashboard.css'));
  const staticBinaryBarCssUri  = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'binary-bar.css'));
  const staticDisasmCssUri     = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'disasm.css'));
  const staticCfgCssUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'cfg.css'));
  const staticDecompileCssUri  = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'decompile.css'));
  const staticSearchCssUri     = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'search.css'));
  const staticAnalysisCssUri   = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'analysis.css'));
  const staticToolsCssUri      = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'tools.css'));
  const dynamicCssUri          = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'panel-dynamic.css'));
  const dynamicRuntimeSessionCssUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'runtime-session.css'));
  const graphicalStackHubCssUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'graphical-stack-hub.css'));
  const dynamicRuntimeLayoutCssUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'runtime-layout.css'));
  const runtimeModuleUri       = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'app', 'main.js'));
  const outilsCssUri           = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'panel-outils.css'));
  const optionsCssUri          = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'panel-options.css'));
  const csp = webview.cspSource;

  return html
    .replace(/{{scriptUri}}/g, scriptUri.toString())
    // shared modules
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
