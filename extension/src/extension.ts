// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file extension.js
 * @brief Entree principale de l'extension VS Code.
 * @details Charge output.json, cree la webview et relie les commandes.
 */

const vscode = require('vscode');
const path = require('path');
const fs = require('fs');

// Treat local `.ts` files as plain CommonJS sources at runtime so the extension
// can launch directly from `src/` without a separate compile step.
if (!require.extensions['.ts']) {
  require.extensions['.ts'] = require.extensions['.js'];
}

const { SidebarSymbolsProvider, SidebarStringsProvider, SidebarSectionsProvider, SidebarCalculatorProvider } = require('./shared/sidebarProvider');
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
} = require('./shared/utils');
const { readTraceJson, writeTraceJson, setViewMode, loadTraceFromWorkspace } = require('./shared/trace');
const { payloadToHex, parseStdinExpression } = require('./shared/payload');
const { getDisasmScript } = require('./shared/paths');
const { registerSharedCommands } = require('./shared/commands');
const { registerStaticCommands } = require('./static/commands');
const { registerDecompilerCommands } = require('./static/decompilerCommands');
const { AuthService } = require('./shared/authService');
const { resolveAuthServerUrl } = require('./shared/authConfig');

const decorationTypes = new Map();


function _migrateFromLegacyPofDir(root, storageDir, globalDir) {
  const legacyDir = path.join(root, '.pile-ou-face');
  if (!fs.existsSync(legacyDir)) return;
  logChannel.appendLine('[storage] Migration legacy .pile-ou-face → storageUri…');

  const copyIfExists = (src, dest) => {
    if (!fs.existsSync(src)) return;
    const destDir = path.dirname(dest);
    if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });
    if (!fs.existsSync(dest)) fs.copyFileSync(src, dest);
  };

  const copyDirIfExists = (src, dest) => {
    if (!fs.existsSync(src)) return;
    let entries;
    try { entries = fs.readdirSync(src, { withFileTypes: true }); } catch (_) { return; }
    for (const e of entries) {
      const srcPath = path.join(src, e.name);
      const destPath = path.join(dest, e.name);
      if (e.isDirectory()) copyDirIfExists(srcPath, destPath);
      else copyIfExists(srcPath, destPath);
    }
  };

  // Configs → storageDir
  copyIfExists(path.join(legacyDir, 'decompilers.json'), path.join(storageDir, 'decompilers.json'));
  copyIfExists(path.join(legacyDir, 'compilers.json'),   path.join(storageDir, 'compilers.json'));

  // Données utilisateur → storageDir
  copyDirIfExists(path.join(legacyDir, 'annotations'),   path.join(storageDir, 'annotations'));
  copyDirIfExists(path.join(legacyDir, 'pfdb'),          path.join(storageDir, 'pfdb'));
  copyDirIfExists(path.join(legacyDir, 'patches'),       path.join(storageDir, 'patches'));
  copyDirIfExists(path.join(legacyDir, 'static_cache'),  path.join(storageDir, 'static_cache'));

  // Plugins → globalDir
  if (globalDir) {
    copyDirIfExists(path.join(legacyDir, 'plugins'), path.join(globalDir, 'plugins'));
  }

  logChannel.appendLine('[storage] Migration terminée. Le dossier .pile-ou-face peut être supprimé manuellement.');
}


/**
 * @brief Active l'extension et enregistre les commandes.
 * @param context Contexte VS Code.
 */
function activate(context) {
  setExtensionPath(context.extensionPath);
  const storageDir  = ensureStorageDir(context);
  const globalDir   = getGlobalStorageDir(context);

  // Ensure Python dependencies are installed at startup
  const folders = vscode.workspace.workspaceFolders;
  if (folders && folders.length > 0) {
    const root = resolveProjectRoot(folders[0].uri.fsPath);
    const pythonExe = detectPythonExecutable(root);
    ensurePythonDependencies(pythonExe, root).catch((err) => {
      logChannel.appendLine(`[Python setup] Warning: ${err.message}`);
    });
  }

  // Migration one-shot depuis l'ancien .pile-ou-face/ (ne tourne qu'une fois)
  if (!context.globalState.get('pof-storage-migration-v1') && folders && folders.length > 0) {
    const legacyRoot = resolveProjectRoot(folders[0].uri.fsPath);
    try {
      _migrateFromLegacyPofDir(legacyRoot, storageDir, globalDir);
      context.globalState.update('pof-storage-migration-v1', true);
    } catch (migErr) {
      logChannel.appendLine(`[storage] Migration error (non-fatal): ${migErr.message || migErr}`);
    }
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

  const openVisualizerWebview = createVisualizer({ context, logChannel, decorationTypes });
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
    openVisualizerWebview
  };
  const openHub = createHub(hubConfig);

  // Commandes partagées (open, goToAddress, calculator)
  const sharedSubs = registerSharedCommands(context, { logChannel, openHub });
  context.subscriptions.push(...sharedSubs);

  // Panneau latéral et refresh
  const root = resolveProjectRoot(vscode.workspace.workspaceFolders?.[0]?.uri?.fsPath || '');
  const savedSettings = context.globalState.get('pof-settings', {});
  const pythonExe = savedSettings.pythonPath || (root ? detectPythonExecutable(root) : 'python3');
  const symbolsProvider = new SidebarSymbolsProvider(root, pythonExe);
  const stringsProvider = new SidebarStringsProvider(root, pythonExe);
  const sectionsProvider = new SidebarSectionsProvider(root, pythonExe);
  const calculatorProvider = new SidebarCalculatorProvider();
  vscode.window.registerTreeDataProvider('pileOuFace.symbols', symbolsProvider);
  vscode.window.registerTreeDataProvider('pileOuFace.strings', stringsProvider);
  vscode.window.registerTreeDataProvider('pileOuFace.sections', sectionsProvider);
  vscode.window.registerTreeDataProvider('pileOuFace.calculator', calculatorProvider);

  const refreshSidebar = (binaryPath) => {
    if (binaryPath) {
      symbolsProvider.refresh(binaryPath);
      stringsProvider.refresh(binaryPath);
      sectionsProvider.refresh(binaryPath);
    }
  };
  const setSidebarMode = (mode) => {
    symbolsProvider.setMode(mode);
    stringsProvider.setMode(mode);
    sectionsProvider.setMode(mode);
  };
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
      cp.execFile(pythonExe, [scriptPath, ...rest], {
        encoding: 'utf8', cwd: cwd || root, maxBuffer, timeout,
        env: buildRuntimeEnv(cwd || root, storageDir),
      }, (err, stdout, stderr) => {
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
  parseStdinExpression
};
