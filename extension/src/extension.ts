// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file extension.js
 * @brief Entree principale de l'extension VS Code.
 * @details Charge output.json, cree la webview et relie les commandes.
 */

const vscode = require('vscode');
const path = require('path');

// Treat local `.ts` files as plain CommonJS sources at runtime so the extension
// can launch directly from `src/` without a separate compile step.
if (!require.extensions['.ts']) {
  require.extensions['.ts'] = require.extensions['.js'];
}

const { ensureStaticAsm } = require('./static/asmBuilder');
const { createVisualizer } = require('./dynamic/visualizer');
const { createHub } = require('./static/hub');
const {
  logChannel,
  getTempDir,
  ensureTempDir,
  runCommand,
  detectPythonExecutable,
  resolveProjectRoot,
  buildRuntimeEnv,
  ensurePythonDependencies,
  check32BitToolchain,
  setExtensionPath,
  ensureStorageDir,
  getGlobalStorageDir,
  logError,
} = require('./shared/utils');
const { readTraceJson, writeTraceJson, setViewMode, loadTraceFromWorkspace } = require('./shared/trace');
const { payloadToHex, parseStdinExpression } = require('./shared/payload');
const { getDisasmScript } = require('./shared/paths');
const { registerSharedCommands } = require('./shared/commands');
const { registerStaticCommands } = require('./static/commands');
const { registerDecompilerCommands } = require('./static/decompilerCommands');
const { AuthService } = require('./shared/authService');
const { resolveAuthServerUrl } = require('./shared/authConfig');
const { getProductConfig } = require('./shared/productConfig');
const { configureRuntimeAudit, recordRuntimeEvent, resetRuntimeAudit } = require('./shared/runtimeAudit');
const { createTelemetryService } = require('./shared/telemetry/telemetry');
const { EVENT_NAMES } = require('./shared/telemetry/telemetryEvents');
const { mapPlatform } = require('./shared/telemetry/telemetryMappings');
const logger = require('./shared/logger');

const decorationTypes = new Map();

// Filet de sécurité : capture les promesses rejetées non gérées et les logue
// via le canal de l'extension au lieu de les laisser invisibles dans la
// console Extension Host. Volontairement limité à unhandledRejection —
// uncaughtException supprimerait le comportement par défaut de Node (qui
// laisse l'extension continuer dans un état potentiellement incohérent après
// une exception non catchée) pour un simple gain de visibilité ; le risque
// sur la stabilité ne vaut pas le compromis.
let _unhandledRejectionHandler = null;

function _formatUnhandledError(prefix, err) {
  const detail = err && err.stack ? err.stack : String(err);
  return `[${prefix}] ${detail}`;
}

// Séparé de l'abonnement process.on(...) pour rester testable directement
// (invoquer la logique sans dépendre du système d'événements réel de Node,
// qui est aussi utilisé par le test runner lui-même).
function _handleGlobalError(prefix, err) {
  logError(_formatUnhandledError(prefix, err));
}

function _registerGlobalErrorHandlers() {
  if (_unhandledRejectionHandler) return;
  _unhandledRejectionHandler = (reason) => _handleGlobalError('unhandledRejection', reason);
  process.on('unhandledRejection', _unhandledRejectionHandler);
}

function _unregisterGlobalErrorHandlers() {
  if (_unhandledRejectionHandler) process.off('unhandledRejection', _unhandledRejectionHandler);
  _unhandledRejectionHandler = null;
}


/**
 * @brief Active l'extension et enregistre les commandes.
 * @param context Contexte VS Code.
 */
function activate(context) {
  setExtensionPath(context.extensionPath);
  _registerGlobalErrorHandlers();
  const productConfig = getProductConfig();
  const telemetry = createTelemetryService({
    vscode,
    context,
    endpoint: productConfig.telemetryProviderUrl,
  });
  telemetry.trackEvent(EVENT_NAMES.EXTENSION_ACTIVATED, {
    extensionVersion: String(context.extension?.packageJSON?.version || '0.0.0'),
    vscodeVersionMajor: String(vscode.version || '0').split('.')[0],
    platform: mapPlatform(process.platform),
  });
  const storageDir  = ensureStorageDir(context);
  const globalDir   = getGlobalStorageDir(context);
  const auditEnabled = vscode.workspace.getConfiguration('pileOuFace').get('runtimeUsageAudit', false);
  configureRuntimeAudit({ storageDir, logChannel, vscode, enabled: auditEnabled === true });

  const applyLogLevelFromConfig = () => {
    const level = vscode.workspace.getConfiguration('pileOuFace').get('logLevel', 'warning');
    logger.setLevel(level);
  };
  applyLogLevelFromConfig();
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('pileOuFace.logLevel')) applyLogLevelFromConfig();
    })
  );

  // Ensure Python dependencies are installed at startup
  const folders = vscode.workspace.workspaceFolders;
  if (folders && folders.length > 0) {
    const root = resolveProjectRoot(folders[0].uri.fsPath);
    const pythonExe = detectPythonExecutable(root);
    ensurePythonDependencies(pythonExe, root, { quiet: true }).catch((err) => {
      logChannel.appendLine(`[Python setup] Warning: ${err.message}`);
    });
  }

  // checkDecompilerDeps supprimé : l'install est proposé à la demande via le dropdown

  const authConfig = vscode.workspace.getConfiguration('pileOuFace').inspect('authServerUrl');
  const authServerUrl = resolveAuthServerUrl({
    savedAuthServerUrl: context.globalState.get('pof-settings', {}).authServerUrl || '',
    configuredAuthServerUrl: authConfig?.workspaceFolderValue || authConfig?.workspaceValue || authConfig?.globalValue || '',
    projectRoot: folders?.[0]?.uri?.fsPath || '',
  });
  const _authService = AuthService.getInstance(context.secrets, authServerUrl);
  _authService.refresh().catch(() => {}); // refresh silencieux au démarrage

  const openVisualizerWebview = createVisualizer({ context, logChannel, decorationTypes, telemetry });
  const hubConfig = {
    context,
    logChannel,
    storageDir,
    globalDir,
    getTempDir,
    ensureTempDir,
    runCommand,
    detectPythonExecutable,
    ensureStaticAsm,
    readTraceJson,
    writeTraceJson,
    setViewMode,
    payloadToHex,
    parseStdinExpression,
    check32BitToolchain,
    openVisualizerWebview,
    telemetry,
  };
  const openHub = createHub(hubConfig);

  // Commandes partagées (open, goToAddress, calculator)
  const sharedSubs = registerSharedCommands(context, { logChannel, openHub });
  context.subscriptions.push(...sharedSubs);

  // Panneau latéral et refresh
  const root = resolveProjectRoot(vscode.workspace.workspaceFolders?.[0]?.uri?.fsPath || '');
  const savedSettings = context.globalState.get('pof-settings', {});
  const pythonExe = savedSettings.pythonPath || (root ? detectPythonExecutable(root) : 'python3');
  const refreshSidebar = (_binaryPath) => {};
  const setSidebarMode = (_mode) => {};
  hubConfig.refreshSidebar = refreshSidebar;
  hubConfig.setSidebarMode = setSidebarMode;

  // Commandes statiques (exportDisasm, xrefs, sidebarRefresh, goToSymbolInDisasm, disasmSection)
  const staticDeps = {
    ensureTempDir,
    storageDir,
    runCommand,
    detectPythonExecutable,
    logChannel,
  };
  const staticProviders = { root, pythonExe, refreshSidebar, openHub };
  const staticSubs = registerStaticCommands(context, staticDeps, staticProviders);
  context.subscriptions.push(...staticSubs);

  // Commandes de gestion des décompilateurs (add, remove, list, test, openConfig)
  const cp = require('child_process');
  const _runPythonForCmds = (argsWithScript, { timeout = 60000, maxBuffer = 4 * 1024 * 1024, cwd } = {}) =>
    new Promise((resolve, reject) => {
      const [scriptRelPath, ...rest] = argsWithScript;
      const scriptPath = require('path').join(cwd || root, scriptRelPath);
      const startedAt = Date.now();
      cp.execFile(pythonExe, [scriptPath, ...rest], {
        encoding: 'utf8', cwd: cwd || root, maxBuffer, timeout,
        env: buildRuntimeEnv(cwd || root, storageDir),
      }, (err, stdout, stderr) => {
        recordRuntimeEvent('python', scriptRelPath, {
          source: 'extension.commands',
          argc: rest.length,
          durationMs: Date.now() - startedAt,
          ok: !err,
          stdoutBytes: Buffer.byteLength(String(stdout || ''), 'utf8'),
          stderrBytes: Buffer.byteLength(String(stderr || ''), 'utf8'),
        });
        if (err) { err.stderr = stderr; reject(err); } else resolve({ stdout });
      });
    });
  const decompilerDeps = { runPython: _runPythonForCmds, logChannel };
  const decompilerSubs = registerDecompilerCommands(context, decompilerDeps, root, storageDir);
  context.subscriptions.push(...decompilerSubs);
}

/**
 * @brief Desactive l'extension (hook VS Code).
 */
function deactivate() {
  _unregisterGlobalErrorHandlers();
  resetRuntimeAudit();
  for (const deco of decorationTypes.values()) {
    deco.dispose();
  }
  decorationTypes.clear();
}

module.exports = {
  activate,
  deactivate,
  loadTraceFromWorkspace,
  payloadToHex,
  parseStdinExpression,
  _registerGlobalErrorHandlers,
  _unregisterGlobalErrorHandlers,
  _formatUnhandledError,
  _handleGlobalError,
};
