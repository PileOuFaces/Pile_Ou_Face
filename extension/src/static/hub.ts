// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file hub.js
 * @brief Hub principal (UI MOSCOW) et gestion des messages webview.
 */

const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cp = require('child_process');
const { getHubContent } = require('../shared/webview');
const { buildRuntimeEnv, resolveProjectRoot, getExtensionPath, logDebug } = require('../shared/utils');
const { AuthService } = require('../shared/authService');
const { resolveAuthServerUrl } = require('../shared/authConfig');
const {
  isSupportedBinary,
  inspectBinaryInput,
  getRawArchDescriptor,
  normalizeRawProfile,
} = require('../shared/sharedHandlers');
const {
  findSymbolByCandidates,
  isMachOFormat,
  mainSymbolCandidates,
  normalizeStartSymbolForBinary,
  preferredMainSymbol,
  symbolLookupCandidates,
} = require('../shared/symbols');
const {
  normalizePayloadTargetMode,
  payloadTargetLabel,
  resolvePayloadTarget,
} = require('../shared/dynamicInputTarget');
const { readCache, writeCache } = require('../shared/staticCache');
const { createHandlers } = require('./handlers');
const {
  getDisasmScript,
  getHeadersScript,
  getSymbolsScript,
  getStringsScript,
  getSectionsScript,
  getCfgScript,
  getBinaryMetadataScript,
  getCallGraphScript,
  getDiscoverFunctionsScript,
  getXrefsScript,
  getRulesManagerScript,
  getSearchScript,
  getOffsetToVaddrScript,
  getAsmStaticScript,
  getRunPipelineScript,
  getPayloadScriptRunnerScript,
  getExampleCandidates,
} = require('../shared/paths');
const { buildTraceSourceEnrichment } = require('../dynamic/sourceCEnrichment');
const { attachTraceAddressEnrichment } = require('../dynamic/traceEnrichment');
const {
  parseIntLiteral,
  parseBigIntLiteral,
  extractAsm,
  normalizeAddress,
  extractFrameOffset,
  regWidthBytes,
  parseCmpInfo,
  normalizeCalleeName,
  detectArchBitsFromLines,
  collectRegOffsets,
  buildCmpPayloadSuggestion,
} = require('./hub/asmUtils');
const { createAnalysisContext } = require('./hub/analysisContext');
const { createNavigation } = require('./hub/navigation');
const { createGraphRenderers } = require('./hub/graphRenderers');
const { createLoaders } = require('./hub/loaders');
const { createTraceHistory } = require('./hub/traceHistory');
const { createActions } = require('./hub/actions');
const archSupport = require('./hub/archSupport');

const AUTH_STRICT_LICENSE_ENV = 'BINHOST_DISABLE_LICENSE_FALLBACK';

/**
 * @brief Crée la fonction openHub.
 * @param config Dependencies: context, logChannel, getTempDir, ensureTempDir, runCommand,
 *   detectPythonExecutable, ensureStaticAsm, readTraceJson, writeTraceJson, setViewMode,
 *   payloadToHex, parseStdinExpression, check32BitToolchain, openVisualizerWebview
 * @return openHub(initialPanel)
 */
function createHub(config) {
  const {
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
    refreshSidebar,
    setSidebarMode
  } = config;

  const SETTINGS_DEFAULTS = {
    pythonPath: '',
    authServerUrl: '',
    aiTemperature: 0.7,
    aiTopP: 0.9,
    aiMaxTokens: 4096,
    aiPricingRules: [],
    decompilerProvider: 'docker',
    decompilerLocalPaths: {},
    stringsEncoding: 'auto',
    stringsMinLen: 4,
    asmSyntax: 'intel',
    lang: 'fr',
    defaultPanel: 'dashboard',
    codeFontSize: 13,
    interfaceMode: 'advanced',
    enabledStaticFeatures: [],
  };

  const RAW_PROFILE_KEY = 'reverse-workspace.raw-profiles';
  const sanitizeKey = (binaryPath) => path.resolve(binaryPath);
  const loadRawProfiles = () => context.workspaceState.get(RAW_PROFILE_KEY, {});
  const getRawProfile = (binaryPath) => {
    const profiles = loadRawProfiles();
    return normalizeRawProfile(profiles[sanitizeKey(binaryPath)]);
  };
  const setRawProfile = async (binaryPath, profile) => {
    const normalized = normalizeRawProfile(profile);
    const profiles = { ...loadRawProfiles() };
    if (normalized) profiles[sanitizeKey(binaryPath)] = normalized;
    else delete profiles[sanitizeKey(binaryPath)];
    await context.workspaceState.update(RAW_PROFILE_KEY, profiles);
  };
  const clearRawProfile = async (binaryPath) => {
    const profiles = { ...loadRawProfiles() };
    delete profiles[sanitizeKey(binaryPath)];
    await context.workspaceState.update(RAW_PROFILE_KEY, profiles);
  };

  let hubPanelRef = null;
  let hubHandlersRef = null;
  let pendingAiPrompt = '';
  let latestTraceRunId = 0;
  const perfDiagnosticsEnabled = () => {
    try {
      return Boolean(vscode.workspace.getConfiguration?.('pileOuFace')?.get?.('perfDiagnostics', false));
    } catch (_) {
      return false;
    }
  };

  context.subscriptions.push(vscode.commands.registerCommand('pileOuFace.perfSnapshot', () => {
    if (!perfDiagnosticsEnabled()) {
      vscode.window.showInformationMessage('Diagnostics performance Pile ou Face désactivés. Activez pileOuFace.perfDiagnostics pour capturer un snapshot.');
      return;
    }
    const mem = process.memoryUsage();
    logChannel.appendLine(`[perf.host] manual.snapshot ${JSON.stringify({
      ts: new Date().toISOString(),
      extensionHostMemory: {
        rss: mem.rss,
        heapUsed: mem.heapUsed,
        heapTotal: mem.heapTotal,
        external: mem.external,
        arrayBuffers: mem.arrayBuffers,
      },
      hubPanelOpen: Boolean(hubPanelRef && !hubPanelRef.disposed),
    })}`);
    if (hubPanelRef && !hubPanelRef.disposed) {
      hubPanelRef.webview.postMessage({ type: 'hubPerfSnapshotRequest', source: 'command' });
    }
    logChannel.show(true);
  }));

  return function openHub(initialPanel = 'dashboard', options = {}) {
    if (options.aiPrompt) pendingAiPrompt = String(options.aiPrompt);
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
      vscode.window.showErrorMessage('Aucun workspace ouvert.');
      return null;
    }
    const workspaceRoot = folders[0].uri.fsPath;
    const root = resolveProjectRoot(folders[0].uri.fsPath);
    const backendRoot = getExtensionPath() || root;
    const pythonExe = detectPythonExecutable(root);
    const pythonEnv = buildRuntimeEnv(root, storageDir);
    const getAuthServerUrl = () => {
      try {
        const authConfig = vscode.workspace.getConfiguration('pileOuFace').inspect('authServerUrl');
        return resolveAuthServerUrl({
          savedAuthServerUrl: context.globalState.get('pof-settings', {}).authServerUrl || '',
          configuredAuthServerUrl: authConfig?.workspaceFolderValue || authConfig?.workspaceValue || authConfig?.globalValue || '',
          projectRoot: root,
        });
      } catch (_) {
        return resolveAuthServerUrl({ projectRoot: root });
      }
    };
    const buildPluginRuntimeEnv = async () => {
      const env = { ...pythonEnv };
      let hasOnlineKeys = false;
      try {
        const authSvc = AuthService.getInstance(
          context.secrets,
          getAuthServerUrl(),
        );
        const keys = await authSvc.getContentKeys();
        const entries = Object.entries(keys);
        if (entries.length > 0) {
          hasOnlineKeys = true;
          for (const [pluginId, key] of entries) {
            const varName = 'POF_CONTENT_KEY_' + String(pluginId).toUpperCase().replace(/-/g, '_').replace(/\./g, '_');
            env[varName] = String(key);
          }
        }
      } catch (_e) {
        // AuthService non disponible — aucune clé injectée.
      }

      if (hasOnlineKeys) {
        // MODE 1 — en ligne : bloquer les fichiers licence offline.
        env[AUTH_STRICT_LICENSE_ENV] = '1';
      } else {
        // Pas de clés en ligne : vérifier la présence de fichiers licence offline signés.
        const licenseDir = path.join(storageDir || path.join(root, '.pile-ou-face'), 'licenses');
        let hasOfflineLicenses = false;
        try {
          const files = fs.readdirSync(licenseDir);
          hasOfflineLicenses = files.some((f) => String(f).endsWith('.license.json'));
        } catch (_e) {
          // Répertoire absent → pas de licences offline.
        }

        if (!hasOfflineLicenses) {
          // Ni clés en ligne, ni licences offline → plugin verrouillé.
          env[AUTH_STRICT_LICENSE_ENV] = '1';
        }
        // MODE 3 — offline contractuel : hasOfflineLicenses=true, flag absent,
        // le runtime Python lira les fichiers .license.json signés.
      }

      return env;
    };
    const runHubStartupAction = async (handlers) => {
      if (!handlers) return;
      if (options.requestBinarySelection) {
        await handlers.requestBinarySelection();
        return;
      }
      const targetBinaryPath = String(options.binaryPath || '').trim();
      if (!targetBinaryPath) return;
      await handlers.hubUseBinaryPath({
        binaryPath: targetBinaryPath,
        binaryMeta: options.binaryMeta || null,
        rawProfileAction: options.rawProfileAction || null,
      });
    };

    if (hubPanelRef && !hubPanelRef.disposed) {
      hubPanelRef.reveal(vscode.ViewColumn.Beside);
      hubPanelRef.webview.postMessage({ type: 'hubPerfDiagnosticsConfig', enabled: perfDiagnosticsEnabled() });
      hubPanelRef.webview.postMessage({ type: 'showPanel', panel: initialPanel, focusGoToAddr: options.focusGoToAddr });
      if (pendingAiPrompt) {
        hubPanelRef.webview.postMessage({ type: 'hubPrefillAiPrompt', prompt: pendingAiPrompt });
        pendingAiPrompt = '';
      }
      globalThis.setTimeout(() => {
        runHubStartupAction(hubHandlersRef).catch((error) => {
          logChannel.appendLine(`[hub] Startup action error: ${error?.message || error}`);
        });
      }, 0);
      return hubPanelRef;
    }

    const panel = vscode.window.createWebviewPanel(
      'pileOuFaceHub',
      'Reverse Workspace',
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [
          context.extensionUri,
          vscode.Uri.file(root),
          ...(storageDir ? [
            vscode.Uri.file(storageDir),
            vscode.Uri.file(path.join(storageDir, 'plugins')),
          ] : []),
        ],
      }
    );
    hubPanelRef = panel;
    panel.onDidDispose(() => {
      hubPanelRef = null;
      hubHandlersRef = null;
    });

    // ── Watcher decompilers.json — actualisation automatique du panneau ─────────
    const _decompilersConfigPath = path.join(storageDir || path.join(root, '.pile-ou-face'), 'decompilers.json');
    const _refreshDecompilerList = async () => {
      try {
        const { stdout } = await new Promise((resolve, reject) => {
          cp.execFile(
            pythonExe,
            [path.join(backendRoot, 'backends/static/decompile/decompile.py'), '--list', '--provider', 'auto'],
            { encoding: 'utf8', cwd: root, maxBuffer: 2 * 1024 * 1024, timeout: 30000, env: pythonEnv },
            (err, stdout, stderr) => err ? reject(Object.assign(err, { stderr })) : resolve({ stdout }),
          );
        });
        const result = JSON.parse(stdout);
        panel.webview.postMessage({ type: 'hubDecompilerList', result });
      } catch (_) {
        return undefined;
      }
    };

    // Watcher sur le fichier de config — debounce 600 ms pour éviter les doubles triggers
    let _decompilerWatchDebounce = null;
    const _decompilerConfigWatcher = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(vscode.Uri.file(storageDir || path.join(root, '.pile-ou-face')), 'decompilers.json'),
    );
    const _onDecompilerConfigChange = () => {
      globalThis.clearTimeout(_decompilerWatchDebounce);
      _decompilerWatchDebounce = globalThis.setTimeout(_refreshDecompilerList, 600);
    };
    _decompilerConfigWatcher.onDidChange(_onDecompilerConfigChange);
    _decompilerConfigWatcher.onDidCreate(_onDecompilerConfigChange);
    _decompilerConfigWatcher.onDidDelete(_onDecompilerConfigChange);
    panel.onDidDispose(() => {
      _decompilerConfigWatcher.dispose();
      globalThis.clearTimeout(_decompilerWatchDebounce);
    });

    // Auto-detect address when user clicks a line in the .disasm.asm file
    const parseDisasmSelectionContext = (lineText) => {
      const text = String(lineText || '');
      const match = text.match(/^\s*(0x[0-9a-fA-F]+)\s*:\s*([0-9a-fA-F ]+)?/);
      if (!match) return null;
      const bytes = String(match[2] || '')
        .trim()
        .split(/\s+/)
        .filter((part) => /^[0-9a-fA-F]{2}$/.test(part));
      return {
        addr: match[1],
        spanLength: Math.max(1, bytes.length || 1),
      };
    };
    const _selectionListener = vscode.window.onDidChangeTextEditorSelection(event => {
      if (!hubPanelRef) { _selectionListener.dispose(); return; }
      const editor = event.textEditor;
      if (!editor.document.fileName.endsWith('.disasm.asm')) return;
      const lineText = editor.document.lineAt(editor.selection.active.line).text;
      const selection = parseDisasmSelectionContext(lineText);
      if (selection?.addr) {
        panel.webview.postMessage({
          type: 'hubActiveAddr',
          addr: selection.addr,
          spanLength: selection.spanLength,
        });
      }
    });
    panel.onDidDispose(() => { _selectionListener.dispose(); });

    // ── Periodic license re-evaluation — every 15 minutes ───────────────────────
    const LICENSE_RECHECK_MS = 15 * 60 * 1000;
    const licenseRecheckTimer = globalThis.setInterval(async () => {
      if (!panel || !panel.visible) return;
      try {
        const pluginEnv = await buildPluginRuntimeEnv();
        const data = await new Promise((resolve, reject) => {
          cp.execFile(
            pythonExe,
            [path.join(backendRoot, 'backends/plugins/runtime.py'), 'list', '--json'],
            { encoding: 'utf8', cwd: root, timeout: 30000, maxBuffer: 4 * 1024 * 1024, env: pluginEnv },
            (err, stdout, stderr) => {
              if (err) { const w = err instanceof Error ? err : new Error(String(err)); w.stderr = stderr; reject(w); return; }
              try { resolve(JSON.parse(stdout || '{}')); } catch (e) { reject(e); }
            },
          );
        });
        panel.webview.postMessage({ type: 'pluginStatusRefresh', payload: data });
      } catch (_err) {
        // Non-critical — next check will retry
      }
    }, LICENSE_RECHECK_MS);
    panel.onDidDispose(() => { globalThis.clearInterval(licenseRecheckTimer); });

    panel.webview.html = getHubContent(panel.webview, context.extensionUri, initialPanel, root, globalDir, storageDir);
    panel.webview.postMessage({ type: 'hubPerfDiagnosticsConfig', enabled: perfDiagnosticsEnabled() });
    const handlerCtx = {
      root,
      storageDir,
      globalDir,
      panel,
      context,
      logChannel,
      getTempDir,
      ensureTempDir,
      refreshSidebar,
      getRawProfile,
      setRawProfile,
      clearRawProfile,
    };
    const handlers = createHandlers(handlerCtx);
    hubHandlersRef = handlers;
    if (options.focusGoToAddr) {
      globalThis.setTimeout(() => {
        panel.webview.postMessage({ type: 'showPanel', panel: initialPanel, focusGoToAddr: true });
      }, 0);
    }
    if (options.requestBinarySelection || options.binaryPath) {
      globalThis.setTimeout(() => {
        runHubStartupAction(handlers).catch((error) => {
          logChannel.appendLine(`[hub] Startup action error: ${error?.message || error}`);
        });
      }, 80);
    }
    // Proactively push rules state to webview on hub open so rules
    // are always visible after reload without relying on DOMContentLoaded.
    globalThis.setTimeout(() => {
      if (typeof handlers.hubListRules === 'function') {
        handlers.hubListRules({}).catch((err) => {
          logChannel.appendLine(`[hub] Rules init error: ${err?.message || err}`);
        });
      }
    }, 200);

    const runPythonJson = (scriptPath, args) => new Promise((resolve, reject) => {
      cp.execFile(pythonExe, [scriptPath, ...args], { encoding: 'utf8', cwd: root, maxBuffer: 32 * 1024 * 1024, timeout: 60000, env: pythonEnv }, (err, stdout) => {
        if (err) { reject(err.message ? err : new Error(String(err))); return; }
        try { resolve(JSON.parse(stdout)); } catch (e) { reject(e); }
      });
    });
    const runPythonJsonViaFile = (scriptPath, args, tmpFile) => new Promise((resolve, reject) => {
      cp.execFile(pythonExe, [scriptPath, ...args, '--output', tmpFile], { cwd: root, timeout: 120000, env: pythonEnv }, (err) => {
        if (err) { reject(err.message ? err : new Error(String(err))); return; }
        try {
          const data = fs.readFileSync(tmpFile, 'utf8');
          try {
            fs.unlinkSync(tmpFile);
          } catch (err) {
            logDebug(`[runPythonJsonViaFile] suppression du fichier temporaire échouée (${tmpFile}): ${err.message || err}`);
          }
          resolve(JSON.parse(data));
        } catch (e) { reject(e); }
      });
    });
    const runPythonJsonFile = (args, {
      timeout = 30000,
      maxBuffer = 4 * 1024 * 1024,
      fallback = '{}',
    } = {}) => new Promise((resolve, reject) => {
      cp.execFile(
        pythonExe,
        args,
        { encoding: 'utf8', cwd: root, timeout, maxBuffer, env: pythonEnv },
        (err, stdout, stderr) => {
          if (err) {
            const wrapped = err instanceof Error ? err : new Error(String(err || 'Commande Python échouée.'));
            wrapped.stderr = stderr;
            wrapped.stdout = stdout;
            reject(wrapped);
            return;
          }
          try {
            resolve(JSON.parse(stdout || fallback));
          } catch (parseErr) {
            const wrapped = parseErr instanceof Error ? parseErr : new Error(String(parseErr || 'JSON invalide.'));
            wrapped.stderr = stderr;
            wrapped.stdout = stdout;
            reject(wrapped);
          }
        }
      );
    });
    const runPythonTextFile = (args, {
      timeout = 30000,
      maxBuffer = 4 * 1024 * 1024,
    } = {}) => new Promise((resolve, reject) => {
      cp.execFile(
        pythonExe,
        args,
        { encoding: 'utf8', cwd: root, timeout, maxBuffer, env: pythonEnv },
        (err, stdout, stderr) => {
          if (err) {
            const wrapped = err instanceof Error ? err : new Error(String(err || 'Commande Python échouée.'));
            wrapped.stderr = stderr;
            wrapped.stdout = stdout;
            reject(wrapped);
            return;
          }
          resolve(String(stdout || ''));
        }
      );
    });
    const buildPluginRequiredPayload = (pluginId, feature, extra = {}) => ({
      ok: false,
      error: `Feature déplacée vers le plugin ${pluginId}`,
      plugin_required: pluginId,
      feature,
      ...extra,
    });
    const invokePluginRuntimeCommand = async (featureId, payload, {
      timeout = 120000,
      pluginId = '',
      feature = featureId,
    } = {}) => {
      try {
        const pluginEnv = await buildPluginRuntimeEnv();
        const response = await new Promise((resolve, reject) => {
          cp.execFile(
            pythonExe,
            [
              path.join(backendRoot, 'backends/plugins/runtime.py'),
              '--host-version', '0.1.0',
              '--api-version', '1',
              'invoke-feature',
              featureId,
              '--payload-json',
              JSON.stringify(payload || {}),
            ],
            { encoding: 'utf8', cwd: root, timeout, maxBuffer: 4 * 1024 * 1024, env: pluginEnv },
            (err, stdout, stderr) => {
              if (err) { const w = err instanceof Error ? err : new Error(String(err)); w.stderr = stderr; reject(w); return; }
              try { resolve(JSON.parse(stdout || '{}')); } catch (e) { reject(e); }
            },
          );
        });
        if (response?.ok === true) return response.result ?? {};
        const available = Array.isArray(response?.available_commands) ? response.available_commands : [];
        if (pluginId && available.length === 0) {
          return buildPluginRequiredPayload(pluginId, feature);
        }
        return {
          ok: false,
          error: String(response?.error || `Échec plugin: ${featureId}`),
          plugin_required: pluginId || undefined,
          feature,
          plugin_command: String(response?.command || ''),
        };
      } catch (error) {
        if (pluginId) return buildPluginRequiredPayload(pluginId, feature);
        return { ok: false, error: String(error?.message || error || `Échec plugin: ${featureId}`) };
      }
    };
    const resolvePathFromWorkspace = (inputPath) => (
      path.isAbsolute(inputPath) ? inputPath : path.join(root, inputPath)
    );
    const toWebviewPath = (absolutePath) => {
      const relPath = path.relative(root, absolutePath);
      return relPath.startsWith('..') ? absolutePath : relPath;
    };
    const readSourceTextForPayloadTarget = (sourcePath = '') => {
      const requestedSourcePath = String(sourcePath || '').trim();
      if (!requestedSourcePath) return '';
      const absoluteSourcePath = resolvePathFromWorkspace(requestedSourcePath);
      if (!fs.existsSync(absoluteSourcePath)) return '';
      try {
        return fs.readFileSync(absoluteSourcePath, 'utf8');
      } catch (_) {
        return '';
      }
    };
    const buildPayloadTargetPreview = ({ sourcePath = '', mode = 'auto', binarySymbols = [] } = {}) => {
      const sourceText = readSourceTextForPayloadTarget(sourcePath);
      const resolved = resolvePayloadTarget({ mode, sourceText, binarySymbols });
      return {
        payloadTargetMode: normalizePayloadTargetMode(mode),
        payloadTargetAuto: resolved.autoTarget,
        payloadTargetEffective: resolved.target,
        payloadTargetReason: resolved.reason
      };
    };
    const buildSourceEnrichmentMeta = ({ sourcePath = '', trace = null, archBits = 64 } = {}) => {
      const requestedSourcePath = String(sourcePath || '').trim();
      if (!requestedSourcePath) return null;

      const absoluteSourcePath = resolvePathFromWorkspace(requestedSourcePath);
      if (!fs.existsSync(absoluteSourcePath)) {
        return {
          sourcePath: toWebviewPath(absoluteSourcePath),
          archBits: Number(archBits) === 32 ? 32 : 64,
          status: 'missing',
          enabled: false,
          message: 'Code source fourni introuvable ; analyse binaire seule.'
        };
      }

      try {
        const sourceContent = fs.readFileSync(absoluteSourcePath, 'utf8');
        return buildTraceSourceEnrichment({
          sourcePath: toWebviewPath(absoluteSourcePath),
          sourceContent,
          trace,
          archBits
        });
      } catch (error) {
        return {
          sourcePath: toWebviewPath(absoluteSourcePath),
          archBits: Number(archBits) === 32 ? 32 : 64,
          status: 'invalid',
          enabled: false,
          message: `Code source non exploitable ; analyse binaire seule. (${error.message || error})`
        };
      }
    };
    const compileCSource = async ({
      sourcePath,
      binaryPath,
      archBits = '64',
      // Anciens params (gardés pour compatibilité avec runTrace)
      useLegacyFlags = false,
      includeExecstack = false,
      pieChoice = 'no',
      // Nouveaux params explicites (hubCompileStaticBinary)
      optim = null,
      debug = null,
      canary = null,
      execstack = null,
      relro = 'off',
      staticLink = false,
      strip = false,
      extraFlags = '',
    }) => {
      if (!sourcePath) throw new Error('Source C requise.');
      if (!binaryPath) throw new Error('Chemin binaire requis.');
      const absoluteSourcePath = resolvePathFromWorkspace(sourcePath);
      if (!fs.existsSync(absoluteSourcePath)) {
        throw new Error(`Source introuvable: ${absoluteSourcePath}`);
      }
      const absoluteBinaryPath = resolvePathFromWorkspace(binaryPath);
      const outputDir = path.dirname(absoluteBinaryPath);
      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }

      const gccArgs = [];
      if (process.platform === 'darwin') gccArgs.push('-arch', 'x86_64');

      // Architecture 32-bit
      if (archBits === '32') {
        const toolchainCheck = check32BitToolchain(logChannel);
        if (!toolchainCheck.ok) {
          throw new Error(toolchainCheck.message || '32-bit toolchain missing.');
        }
        gccArgs.push('-m32');
      }

      // Optimisation et debug
      if (useLegacyFlags) {
        gccArgs.push('-O0', '-g');
      } else {
        gccArgs.push(optim || '-O0');
        const dbg = debug !== null ? debug : '-g';
        if (dbg) gccArgs.push(dbg);
      }

      // Stack canary
      if (useLegacyFlags) {
        gccArgs.push('-fno-stack-protector');
      } else {
        const c = canary || 'off';
        if (c === 'off')         gccArgs.push('-fno-stack-protector');
        else if (c === 'basic')  gccArgs.push('-fstack-protector');
        else if (c === 'strong') gccArgs.push('-fstack-protector-strong');
        else if (c === 'all')    gccArgs.push('-fstack-protector-all');
      }

      // execstack (Linux seulement)
      const useExecstack = execstack !== null ? execstack : includeExecstack;
      if (useExecstack && process.platform === 'linux') gccArgs.push('-z', 'execstack');

      // PIE
      if (process.platform !== 'darwin') {
        if (pieChoice === 'yes') gccArgs.push('-fpie', '-pie');
        else                     gccArgs.push('-fno-pie', '-no-pie');
      }

      // RELRO (Linux seulement)
      if (process.platform === 'linux') {
        if (relro === 'partial')     gccArgs.push('-Wl,-z,relro');
        else if (relro === 'full')   gccArgs.push('-Wl,-z,relro,-z,now');
      }

      // Linking statique
      if (staticLink) gccArgs.push('-static');

      // Strip
      if (strip) gccArgs.push('-s');

      // Flags custom
      if (extraFlags) {
        const parts = extraFlags.split(/\s+/).filter(Boolean);
        gccArgs.push(...parts);
      }

      gccArgs.push('-o', absoluteBinaryPath, absoluteSourcePath);
      await runCommand('gcc', gccArgs, root, logChannel);
      // macOS crée un bundle .dSYM à côté du binaire — on le supprime
      if (process.platform === 'darwin') {
        const dSYMPath = absoluteBinaryPath + '.dSYM';
        if (fs.existsSync(dSYMPath)) {
          fs.rmSync(dSYMPath, { recursive: true, force: true });
          logChannel.appendLine(`[compile] Suppression ${path.basename(dSYMPath)}`);
        }
      }
      return { absoluteBinaryPath, pathForWebview: toWebviewPath(absoluteBinaryPath) };
    };
    // ── Module instantiation ──────────────────────────────────────────────────
    const analysisCtx = createAnalysisContext({
      root, storageDir, globalDir, pythonExe, logChannel, runCommand, runPythonJson, runPythonTextFile,
      resolvePathFromWorkspace, toWebviewPath, ensureTempDir, getRawProfile,
      vscode, fs, path, crypto,
      inspectBinaryInput, normalizeRawProfile, getRawArchDescriptor,
      readCache, writeCache,
      getDisasmScript, getHeadersScript, getSymbolsScript, getOffsetToVaddrScript,
      getDiscoverFunctionsScript, getExampleCandidates, normalizeAddress,
    });
    const navHandlers = createNavigation({
      panel, analysisCtx, logChannel, vscode, fs, path,
      normalizeAddress, parseIntLiteral, symbolLookupCandidates, isMachOFormat,
    });
    const graphHandlers = createGraphRenderers({
      panel, analysisCtx, root, storageDir, globalDir, runPythonJson, ensureTempDir, logChannel, vscode, fs, path,
      getCfgScript, getCallGraphScript, getDiscoverFunctionsScript,
    });
    const loadersHandlers = createLoaders({
      panel, analysisCtx, root, storageDir, globalDir, runPythonJson, runPythonJsonViaFile, logChannel, fs, path,
      readCache, writeCache, getStringsScript, getSectionsScript, getXrefsScript,
    });
    const traceHistoryHandlers = createTraceHistory({
      panel, root, storageDir, globalDir, ensureTempDir, readTraceJson, writeTraceJson, setViewMode,
      buildSourceEnrichmentMeta, attachTraceAddressEnrichment,
      payloadTargetLabel, normalizePayloadTargetMode, openVisualizerWebview,
      vscode, fs, path, crypto,
    });
    const actionsHandlers = createActions({
      panel, context, vscode, root, workspaceRoot, storageDir, globalDir, logChannel, fs, path,
      runPythonJson, runPythonJsonFile,
      ensureTempDir, getTempDir,
      resolvePathFromWorkspace, toWebviewPath,
      analysisCtx, handlers,
      compileCSource, invokePluginRuntimeCommand,
      payloadToHex, buildCmpPayloadSuggestion,
      isSupportedBinary, inspectBinaryInput,
      getRulesManagerScript, getSearchScript, getPayloadScriptRunnerScript, getExampleCandidates,
      SETTINGS_DEFAULTS,
      setSidebarMode, refreshSidebar,
      normalizePayloadTargetMode, payloadTargetLabel, resolvePayloadTarget,
      preferredMainSymbol, findSymbolByCandidates, mainSymbolCandidates,
    });
    const hubDispatchMap = {
      ...navHandlers,
      ...graphHandlers,
      ...loadersHandlers,
      ...actionsHandlers,
      requestDynamicTraceHistory: traceHistoryHandlers.requestDynamicTraceHistory,
      openDynamicTraceHistory: traceHistoryHandlers.openDynamicTraceHistory,
      deleteDynamicTraceHistory: traceHistoryHandlers.deleteDynamicTraceHistory,
      clearDynamicTraceHistory: traceHistoryHandlers.clearDynamicTraceHistory,
      hubReady: () => {
        panel.webview.postMessage({ type: 'hubPerfDiagnosticsConfig', enabled: perfDiagnosticsEnabled() });
        if (!pendingAiPrompt) return;
        panel.webview.postMessage({ type: 'hubPrefillAiPrompt', prompt: pendingAiPrompt });
        pendingAiPrompt = '';
      },
    };
    panel.webview.onDidReceiveMessage(async (message) => {
      if (!message || !message.type) return;

      const dispatchedHandler = hubDispatchMap[message.type];
      if (dispatchedHandler) {
        try {
          await dispatchedHandler(message);
        } catch (e) {
          logChannel.appendLine(`[hub] Handler error (${message.type}): ${e.message || e}`);
        }
        return;
      }

      const normalizePayloadExpression = (input) => (
        typeof parseStdinExpression === 'function'
          ? parseStdinExpression(input)
          : String(input || '')
      );
      const normalizeInputHex = (value) => {
        const cleaned = String(value || '').replace(/\s+/g, '').replace(/^0x/i, '');
        if (!cleaned) return '';
        if (!/^[0-9a-f]+$/i.test(cleaned) || cleaned.length % 2 !== 0) {
          throw new Error('payloadBytesHex invalide.');
        }
        return cleaned.toLowerCase();
      };
      const hexContainsNullByte = (hex) => (String(hex || '').match(/../g) || []).includes('00');
      const hexToLatin1String = (hex) => Buffer.from(hex, 'hex').toString('latin1');
      const normalizeTraceInputMeta = (input, fallbackMode = 'payload_builder') => {
        const source = input && typeof input === 'object' ? input : {};
        const requestedMode = String(source.mode || fallbackMode || 'payload_builder').trim().toLowerCase();
        const mode = requestedMode === 'simple' || requestedMode === 'python'
          ? 'payload_builder'
          : (['payload_builder', 'file', 'exploit_helper', 'pwntools_script'].includes(requestedMode) ? requestedMode : fallbackMode);
        return {
          mode,
          template: String(source.template || source.sourceFields?.template || '').trim(),
          targetMode: source.targetMode ? normalizePayloadTargetMode(source.targetMode) : '',
          payloadBytesHex: normalizeInputHex(source.payloadBytesHex || ''),
          sourceFields: source.sourceFields && typeof source.sourceFields === 'object' ? source.sourceFields : {},
          generatedSnippet: String(source.generatedSnippet || ''),
          size: Number.isFinite(Number(source.size)) ? Number(source.size) : 0,
          previewHex: String(source.previewHex || '').trim(),
          previewAscii: String(source.previewAscii || ''),
          warnings: Array.isArray(source.warnings) ? source.warnings.map(String) : [],
          sourceFileName: String(source.sourceFileName || source.sourceFields?.sourceFileName || '').trim(),
          selectedCaptureKind: String(source.selectedCaptureKind || source.sourceFields?.selectedCaptureKind || '').trim(),
          target: String(source.target || source.sourceFields?.target || '').trim(),
          builderLevel: String(source.builderLevel || source.sourceFields?.builderLevel || (requestedMode === 'python' ? 'advanced' : 'beginner')).trim(),
        };
      };
      const stageDynamicInputFile = (fileSpec) => {
        const file = fileSpec && typeof fileSpec === 'object' ? fileSpec : null;
        if (!file) return null;
        const source = file.source === 'path' ? 'path' : 'inline';
        const guestPath = String(file.guestPath || '/tmp/pof-input.txt').trim() || '/tmp/pof-input.txt';
        const passAs = file.passAs === 'argv1' ? 'argv1' : 'argv1';
        let hostPath = '';
        if (source === 'path') {
          hostPath = resolvePathFromWorkspace(String(file.hostPath || '').trim());
          if (!hostPath || !fs.existsSync(hostPath)) throw new Error(`Fichier payload introuvable: ${hostPath}`);
        } else {
          const dir = storageDir;
          hostPath = path.join(dir, `dynamic-input-${Date.now()}-${Math.random().toString(16).slice(2)}.txt`);
          fs.writeFileSync(hostPath, String(file.inlineContent || ''), 'utf8');
        }
        return { source, guestPath, hostPath, passAs };
      };
      const sanitizeArtifactToken = (value, fallback = 'item') => {
        const text = String(value || '').trim();
        const safe = text.replace(/[^a-zA-Z0-9._-]/g, '_').replace(/_+/g, '_');
        return safe || fallback;
      };
      const buildPseudoRawInfo = (binaryPath, rawProfile) => {
        const stats = fs.statSync(binaryPath);
        const arch = rawProfile?.arch || 'unknown';
        const descriptor = getRawArchDescriptor(arch);
        return {
          format: 'RAW',
          machine: descriptor.displayName || 'Raw blob',
          entry: rawProfile?.baseAddr || '0x0',
          type: 'blob',
          bits: descriptor.bits || '',
          stripped: 'n/a',
          arch,
          endianness: rawProfile?.endian || 'little',
          interp: 'n/a',
          size: stats.size,
        };
      };
      const ensureDiscoveredFunctionsArtifact = async ({
        artifacts,
        absPath,
        mappingPath,
        baseName,
      }) => {
        const discoveredPath = artifacts?.discoveredPath || path.join(storageDir, `${baseName}.discovered.json`);
        if (fs.existsSync(discoveredPath)) return discoveredPath;
        if (!fs.existsSync(mappingPath)) return null;
        const discScript = getDiscoverFunctionsScript(root);
        const binArg = (artifacts?.binaryMeta?.kind === 'raw')
          ? null
          : ((absPath && fs.existsSync(absPath) && !fs.statSync(absPath).isDirectory()) ? absPath : null);
        const args = [discScript, '--mapping', mappingPath];
        if (binArg) args.push('--binary', binArg);
        const functions = await runPythonJson(discScript, args.slice(1));
        fs.writeFileSync(discoveredPath, JSON.stringify(functions, null, 2), 'utf8');
        return discoveredPath;
      };
      const loadLatestTrace = () => {
        try {
          const outputJsonPath = path.resolve(storageDir || getTempDir(root), 'output.json');
          if (!fs.existsSync(outputJsonPath)) return null;
          return JSON.parse(fs.readFileSync(outputJsonPath, 'utf8'));
        } catch (_) {
          return null;
        }
      };
      const inferPie = (headerInfo, previousTrace) => {
        if (typeof previousTrace?.meta?.elf_pie === 'boolean') return previousTrace.meta.elf_pie;
        const type = String(headerInfo?.type || '').toLowerCase();
        const format = String(headerInfo?.format || '').toLowerCase();
        if (type.includes('dyn')) return true;
        if (type.includes('exec')) return false;
        if (format.includes('pie executable')) return true;
        return false;
      };
      const loadBinaryHeaders = async (binaryPath) => runPythonJson(getHeadersScript(root), ['--binary', binaryPath]);
      const loadBinaryMetadata = async (binaryPath) => {
        try {
          return await runPythonJson(getBinaryMetadataScript(root), [binaryPath]);
        } catch (err) {
          return {
            binary: {
              path: binaryPath,
              format: 'UNKNOWN',
              arch: '',
              bits: null,
              entry: '0x0',
              base: '0x0',
              pie: false,
              stripped: false,
            },
            sections: [],
            symbols: [],
            functions: [],
            plt: [],
            runtime: { base: '0x0', entry: '0x0', pie: false },
            diagnostics: [{
              source: 'build_binary_metadata.py',
              message: String(err?.message || err || 'metadata unavailable'),
            }],
          };
        }
      };
      const loadBinarySymbols = async (binaryPath, { includeAll = false } = {}) => {
        const args = ['--binary', binaryPath];
        if (includeAll) args.push('--all');
        const rawSymbols = await runPythonJson(getSymbolsScript(root), args).catch(() => []);
        return Array.isArray(rawSymbols) ? rawSymbols : (rawSymbols.symbols || []);
      };
      const getBinaryAnnotationsJsonPath = (absPath) => {
        const hash = crypto
          .createHash('sha256')
          .update(absPath)
          .update(fs.existsSync(absPath) ? String(fs.statSync(absPath).mtimeMs) : '')
          .digest('hex')
          .slice(0, 16);
        return path.join(storageDir || path.join(root, '.pile-ou-face'), 'annotations', `${hash}.json`);
      };

      const buildRunTraceInit = async (forcedBinaryPath = '', preset = null, forcedSourcePath = '', payloadTargetMode = 'auto') => {
        const requestedPayloadTargetMode = normalizePayloadTargetMode(preset?.payloadTargetMode || payloadTargetMode);
        const latestTrace = loadLatestTrace();
        const traceBinary = String(latestTrace?.meta?.binary || '').trim();
        const fallbackBinary = getExampleCandidates(root, 'stack3').find((candidate) => fs.existsSync(candidate)) || '';
        const requestedBinary = String(forcedBinaryPath || '').trim();
        const selectedBinary = requestedBinary || traceBinary || fallbackBinary;
        const absoluteBinaryPath = selectedBinary ? resolvePathFromWorkspace(selectedBinary) : '';

        if (!absoluteBinaryPath || !fs.existsSync(absoluteBinaryPath)) {
          const defaultMain = preferredMainSymbol('');
          return {
            binaryPath: '',
            sourcePath: '',
            sourceEnrichmentEnabled: false,
            sourceEnrichmentStatus: '',
            sourceEnrichmentMessage: '',
            payloadTargetMode: requestedPayloadTargetMode,
            payloadTargetAuto: 'argv1',
            payloadTargetEffective: requestedPayloadTargetMode === 'auto'
              ? 'argv1'
              : requestedPayloadTargetMode,
            payloadTargetReason: requestedPayloadTargetMode === 'auto'
              ? 'Auto: aucune source claire, fallback sur argv[1]'
              : `${payloadTargetLabel(requestedPayloadTargetMode)} force manuellement`,
            archBits: 64,
            pie: false,
            symbols: { startDefault: defaultMain, stopDefault: '' },
            mvpProfile: {
              bufferOffset: null,
              bufferSize: null,
              maxSteps: 800,
              startSymbol: defaultMain,
              stopSymbol: ''
            }
          };
        }

        const info = await loadBinaryHeaders(absoluteBinaryPath).catch(() => ({}));
        const symbols = await loadBinarySymbols(absoluteBinaryPath);
        const inputSymbols = await loadBinarySymbols(absoluteBinaryPath, { includeAll: true });
        const sameBinaryTrace = (() => {
          const previousBinary = String(latestTrace?.meta?.binary || '').trim();
          if (!previousBinary) return null;
          const resolvedPrevious = path.normalize(resolvePathFromWorkspace(previousBinary));
          if (resolvedPrevious !== path.normalize(absoluteBinaryPath)) return null;
          return latestTrace;
        })();
        const inferredArchBits = Number(
          info?.bits
          || sameBinaryTrace?.meta?.arch_bits
          || (String(info?.arch || '').includes('64') ? 64 : 32)
        );
        const archBits = inferredArchBits === 32 ? 32 : 64;
        const startDefault = findSymbolByCandidates(symbols, mainSymbolCandidates(info)) || preferredMainSymbol(info);
        const stopDefault = '';
        const defaultProfile = {
          bufferOffset: null,
          bufferSize: null,
          maxSteps: 800,
          startSymbol: startDefault,
          stopSymbol: stopDefault
        };
        const trustedBufferSource = sameBinaryTrace?.meta?.buffer_source === 'detected'
          || sameBinaryTrace?.meta?.buffer_source === 'user';
        const hasSameBinaryBuffer = trustedBufferSource
          && Number.isFinite(Number(sameBinaryTrace?.meta?.buffer_offset))
          && Number.isFinite(Number(sameBinaryTrace?.meta?.buffer_size));
        const mergedProfile = {
          ...defaultProfile,
          ...(hasSameBinaryBuffer
            ? {
              bufferOffset: Number(sameBinaryTrace.meta.buffer_offset),
              bufferSize: Number(sameBinaryTrace.meta.buffer_size)
            }
            : {}),
          ...(Number.isFinite(Number(sameBinaryTrace?.meta?.steps)) && Number(sameBinaryTrace.meta.steps) > 0
            ? { maxSteps: Math.max(800, Number(sameBinaryTrace.meta.steps)) }
            : {}),
          ...(preset?.suggestedOffset !== undefined ? { bufferOffset: preset.suggestedOffset } : {}),
          ...(preset?.suggestedCaptureSize !== undefined ? { bufferSize: preset.suggestedCaptureSize } : {}),
          ...(preset?.maxSteps !== undefined ? { maxSteps: preset.maxSteps } : {}),
          ...(preset?.startSymbol ? { startSymbol: preset.startSymbol } : {}),
          ...(preset?.targetSymbol ? { stopSymbol: preset.targetSymbol } : {}),
          ...(typeof preset?.payloadExpr === 'string' ? { argvPayload: preset.payloadExpr } : {})
        };

        const selectedSourcePath = String(
          forcedSourcePath
          || preset?.sourcePath
          || ''
        ).trim();
        const previousSourcePath = String(
          sameBinaryTrace?.meta?.source_enrichment?.sourcePath
          || sameBinaryTrace?.meta?.source
          || ''
        ).trim();
        const selectedMatchesPreviousSource = Boolean(selectedSourcePath && previousSourcePath)
          && path.normalize(resolvePathFromWorkspace(selectedSourcePath))
            === path.normalize(resolvePathFromWorkspace(previousSourcePath));
        const payloadTargetPreview = buildPayloadTargetPreview({
          sourcePath: selectedSourcePath,
          mode: requestedPayloadTargetMode,
          binarySymbols: inputSymbols
        });

        return {
          binaryPath: toWebviewPath(absoluteBinaryPath),
          sourcePath: selectedSourcePath,
          sourceEnrichmentEnabled: selectedMatchesPreviousSource
            ? sameBinaryTrace?.meta?.source_enrichment?.enabled === true
            : false,
          sourceEnrichmentStatus: selectedMatchesPreviousSource
            ? String(sameBinaryTrace?.meta?.source_enrichment?.status || '').trim()
            : '',
          sourceEnrichmentMessage: selectedMatchesPreviousSource
            ? String(sameBinaryTrace?.meta?.source_enrichment?.message || '').trim()
            : '',
          ...payloadTargetPreview,
          archBits,
          pie: inferPie(info, sameBinaryTrace),
          symbols: { startDefault, stopDefault },
          mvpProfile: mergedProfile
        };
      };
      const sharedHandler = handlers[message.type];
      if (sharedHandler) {
        try {
          await sharedHandler(message);
        } catch (e) {
          logChannel.appendLine(`[hub] Handler error (${message.type}): ${e.message || e}`);
        }
        return;
      }
      if (message.type !== 'runTrace') return;
      const traceRunId = ++latestTraceRunId;
      const payload = (message.payload && typeof message.payload === 'object')
        ? message.payload
        : ((message.config && typeof message.config === 'object') ? message.config : {});

      const sourcePath = (payload.sourcePath || '').trim();
      const binaryPath = (payload.binaryPath || '').trim();
      const useExistingBinary = payload.useExistingBinary !== false;
      const archBits = String(payload.archBits || '64');
      const pieChoice = String(payload.pieChoice || (payload.pie === true ? 'yes' : 'no') || 'no');
      const traceMode = String(payload.traceMode || 'dynamic');
      const hasBufferOffset = payload.bufferOffset !== null && payload.bufferOffset !== undefined && payload.bufferOffset !== '';
      const hasBufferSize = payload.bufferSize !== null && payload.bufferSize !== undefined && payload.bufferSize !== '';
      const bufferOffset = hasBufferOffset ? String(payload.bufferOffset) : null;
      const bufferSize = hasBufferSize ? String(payload.bufferSize) : null;
      const maxSteps = String(payload.maxSteps || '800');

      let startSymbol = String(payload.startSymbol || 'main').trim();
      if (!startSymbol) startSymbol = 'main';
      const stopSymbol = String(payload.stopSymbol || '').trim();
      const useInterp = false;
      const captureBinaryOnly = payload.captureBinaryOnly !== false;

      try {
        const tempDir = storageDir || ensureTempDir(root);
        const { canonicalJsonPath, isolatedJsonPath } = traceHistoryHandlers.buildTraceRunArtifacts(tempDir, traceRunId);
        logChannel.appendLine(`[temp] Sortie trace #${traceRunId}: ${isolatedJsonPath}`);

        if (traceMode === 'static') {
          const absoluteAsm = path.join(tempDir, 'input.asm');
          const absoluteSource = sourcePath ? (path.isAbsolute(sourcePath) ? sourcePath : path.join(root, sourcePath)) : null;
          const staticResult = ensureStaticAsm(absoluteAsm, absoluteSource, logChannel);
          if (!staticResult.ok) {
            vscode.window.showErrorMessage(staticResult.error || 'Static: generation input.asm echouee.');
            return;
          }
          const staticArgs = [
            getAsmStaticScript(root),
            '--input', absoluteAsm,
            '--output', isolatedJsonPath
          ];
          await runCommand(pythonExe, staticArgs, root, logChannel, { PYTHONPATH: getExtensionPath() || root });
          if (!fs.existsSync(isolatedJsonPath)) {
            throw new Error(`Trace statique introuvable: ${path.basename(isolatedJsonPath)}`);
          }
          if (traceRunId !== latestTraceRunId) {
            logChannel.appendLine(`[trace] Resultat perime ignore (#${traceRunId}).`);
            return;
          }
          const trace = readTraceJson(isolatedJsonPath);
          traceHistoryHandlers.enrichTraceForVisualizer(trace, {
            jsonPath: isolatedJsonPath,
            traceRunId,
            viewMode: 'static'
          });
          writeTraceJson(isolatedJsonPath, trace);
          traceHistoryHandlers.setActiveDynamicTracePath(isolatedJsonPath);
          writeTraceJson(canonicalJsonPath, trace);
          openVisualizerWebview(trace);
          traceHistoryHandlers.postDynamicTraceHistory();
        } else {
          if (useExistingBinary && !binaryPath) {
            vscode.window.showErrorMessage('Chemin binaire requis.');
            return;
          }
          if (!useExistingBinary && !sourcePath) {
            vscode.window.showErrorMessage('Source C requise.');
            return;
          }

          let binaryOutPath = '';
          if (useExistingBinary) {
            const absoluteBinaryPath = resolvePathFromWorkspace(binaryPath);
            if (!fs.existsSync(absoluteBinaryPath)) {
              vscode.window.showErrorMessage(`Binaire introuvable: ${absoluteBinaryPath}`);
              return;
            }
            binaryOutPath = absoluteBinaryPath;
          } else {
            const sourceBase = path.parse(sourcePath).name || 'binary';
            const requestedName = binaryPath ? path.basename(binaryPath) : `${sourceBase}.elf`;
            const outputName = requestedName || `${sourceBase}.elf`;
            const outPath = path.resolve(tempDir, outputName);
            const compileResult = await compileCSource({
              sourcePath,
              binaryPath: outPath,
              archBits,
              pieChoice,
              useLegacyFlags: true,
              includeExecstack: true,
            });
            binaryOutPath = compileResult.absoluteBinaryPath;
          }
          const binaryInfoForSymbols = await loadBinaryHeaders(binaryOutPath).catch(() => inspectBinaryInput(binaryOutPath));
          startSymbol = normalizeStartSymbolForBinary(startSymbol, binaryInfoForSymbols);

          const payloadExprRaw = String(payload.payloadExpr || '').trim();
          const inputMeta = normalizeTraceInputMeta(payload.input || null, 'payload_builder');
          const stagedInputFile = inputMeta.mode === 'file'
            ? stageDynamicInputFile(payload.file || payload.input?.file || null)
            : null;
          if (inputMeta.mode === 'file' && !stagedInputFile) {
            throw new Error('Configuration fichier payload manquante.');
          }
          const payloadTargetMode = normalizePayloadTargetMode(
            inputMeta.targetMode || payload.payloadTargetMode || payload.payloadTarget || 'auto'
          );
          const effectiveSourcePath = sourcePath;
          const inputSymbols = await loadBinarySymbols(binaryOutPath, { includeAll: true });
          const payloadTargetResolution = resolvePayloadTarget({
            mode: payloadTargetMode,
            sourceText: readSourceTextForPayloadTarget(effectiveSourcePath),
            binarySymbols: inputSymbols
          });
          const payloadTarget = stagedInputFile ? 'argv1' : payloadTargetResolution.target;
          const inputPayloadHex = inputMeta.payloadBytesHex;
          const injectPayload = !stagedInputFile
            && ((payloadExprRaw.length > 0 || inputPayloadHex.length > 0)
              && (payload.injectPayload === true || payload.injectPayload === undefined));
          const injectStdin = injectPayload && (payloadTarget === 'stdin' || payloadTarget === 'both');
          const injectArgv = injectPayload && (payloadTarget === 'argv1' || payloadTarget === 'both');
          let payloadString = '';
          let payloadHex = '';
          if (injectPayload && inputPayloadHex) {
            payloadHex = inputPayloadHex;
            payloadString = hexToLatin1String(payloadHex);
          } else if (injectPayload && payloadExprRaw) {
            try {
              payloadString = normalizePayloadExpression(payloadExprRaw);
              payloadHex = typeof payloadToHex === 'function' ? payloadToHex(payloadExprRaw) : '';
            } catch (err) {
              vscode.window.showErrorMessage(`Payload invalide: ${err.message || err}`);
              return;
            }
          }
          if (injectArgv && payloadHex && hexContainsNullByte(payloadHex)) {
            vscode.window.showErrorMessage('Payload invalide pour argv[1]: contient un octet NUL. Utilisez stdin ou Fichier.');
            return;
          }
          logChannel.appendLine(`[payload] runTrace mode=${stagedInputFile ? 'file' : inputMeta.mode} target=${payloadTarget} inject=${injectPayload} size=${payloadHex ? payloadHex.length / 2 : payloadString.length} hex=${payloadHex ? payloadHex.slice(0, 160) : ''}`);

          const pythonArgs = [
            getRunPipelineScript(root),
            '--binary', binaryOutPath,
            '--stdin', injectStdin && !payloadHex ? payloadString : '',
            '--stack-entries', '40',
            '--output', isolatedJsonPath,
            '--start-symbol', startSymbol,
            '--max-steps', maxSteps
          ];
          if (bufferOffset !== null) pythonArgs.push('--buffer-offset', bufferOffset);
          if (bufferSize !== null) pythonArgs.push('--buffer-size', bufferSize);
          if (injectStdin && payloadHex) pythonArgs.push('--stdin-hex', payloadHex);
          if (injectArgv && payloadHex) pythonArgs.push('--argv1-hex', payloadHex);
          else if (injectArgv) pythonArgs.push('--argv1', payloadString);
          if (stagedInputFile) {
            pythonArgs.push('--argv1', stagedInputFile.guestPath);
            pythonArgs.push('--virtual-file', `${stagedInputFile.guestPath}=${stagedInputFile.hostPath}`);
          }
          if (!captureBinaryOnly) pythonArgs.push('--no-capture-binary');
          if (stopSymbol) pythonArgs.push('--stop-symbol', stopSymbol);
          if (useInterp) pythonArgs.push('--start-interp');

          await runCommand(pythonExe, pythonArgs, root, logChannel, { PYTHONPATH: getExtensionPath() || root });
          if (!fs.existsSync(isolatedJsonPath)) {
            throw new Error(`Trace dynamique introuvable: ${path.basename(isolatedJsonPath)}`);
          }
          if (traceRunId !== latestTraceRunId) {
            logChannel.appendLine(`[trace] Resultat perime ignore (#${traceRunId}).`);
            return;
          }
          const trace = readTraceJson(isolatedJsonPath);
          traceHistoryHandlers.enrichTraceForVisualizer(trace, {
            jsonPath: isolatedJsonPath,
            traceRunId,
            sourcePath: effectiveSourcePath,
            archBits,
            viewMode: 'dynamic',
            symbols: inputSymbols
          });
          trace.meta = trace.meta && typeof trace.meta === 'object' ? trace.meta : {};
          trace.meta.payload_target_mode = payloadTargetMode;
          trace.meta.payload_target = payloadTarget;
          trace.meta.payload_target_auto = payloadTargetResolution.autoTarget;
          trace.meta.payload_target_reason = payloadTargetResolution.reason;
          trace.meta.payload_label = payloadTargetLabel(payloadTarget);
          trace.meta.payload_text = stagedInputFile ? stagedInputFile.guestPath : (injectPayload ? payloadString : '');
          trace.meta.payload_hex = injectPayload ? payloadHex : '';
          const runtimeInputWarnings = Array.isArray(trace.meta.virtual_file_warnings)
            ? trace.meta.virtual_file_warnings.map(String)
            : [];
          trace.meta.input = {
            mode: stagedInputFile ? 'file' : inputMeta.mode,
            template: inputMeta.template,
            targetMode: payloadTargetMode,
            sourceFileName: inputMeta.sourceFileName,
            selectedCaptureKind: inputMeta.selectedCaptureKind,
            target: inputMeta.target || payloadTarget,
            builderLevel: inputMeta.builderLevel,
            sourceFields: inputMeta.sourceFields,
            generatedSnippet: inputMeta.generatedSnippet,
            size: inputMeta.size || (payloadHex ? payloadHex.length / 2 : payloadString.length),
            previewHex: inputMeta.previewHex || payloadHex,
            previewAscii: inputMeta.previewAscii || payloadString,
            warnings: [...inputMeta.warnings, ...runtimeInputWarnings],
            ...(stagedInputFile ? {
              file: {
                source: stagedInputFile.source,
                guestPath: stagedInputFile.guestPath,
                hostPath: stagedInputFile.hostPath,
                passAs: stagedInputFile.passAs,
              }
            } : {})
          };
          trace.meta.binary_metadata = await loadBinaryMetadata(binaryOutPath);
          writeTraceJson(isolatedJsonPath, trace);
          traceHistoryHandlers.setActiveDynamicTracePath(isolatedJsonPath);
          writeTraceJson(canonicalJsonPath, trace);
          panel.webview.postMessage({
            type: 'dynamicTraceReady',
            traceRunId: (trace.meta?.trace_run_id !== undefined && trace.meta?.trace_run_id !== null)
              ? String(trace.meta.trace_run_id) : null,
            snapshots: Array.isArray(trace.snapshots) ? trace.snapshots : [],
            meta: trace.meta && typeof trace.meta === 'object' ? trace.meta : {},
            crash: trace.crash && typeof trace.crash === 'object' ? trace.crash : null,
            diagnostics: Array.isArray(trace.diagnostics) ? trace.diagnostics : [],
            risks: Array.isArray(trace.risks) ? trace.risks : [],
            // Same field the standalone visualizer's 'init' message carries
            // (visualizer.ts::sendInitToWebview) -- the embedded Hub Runtime
            // view must see the same per-step Evidence, not just snapshots.
            analysisByStep: trace.analysisByStep && typeof trace.analysisByStep === 'object' ? trace.analysisByStep : {},
            enrichment: trace.enrichment && typeof trace.enrichment === 'object' ? trace.enrichment : {},
            tracePath: isolatedJsonPath,
          });
          traceHistoryHandlers.postDynamicTraceHistory();
        }
      } catch (err) {
        vscode.window.showErrorMessage(`Trace failed: ${err.message || err}`);
      } finally {
        if (traceRunId === latestTraceRunId) {
          panel.webview.postMessage({ type: 'runTraceDone' });
        }
      }
    });
    if (pendingAiPrompt) {
      globalThis.setTimeout(() => {
        if (!pendingAiPrompt || !hubPanelRef || hubPanelRef.disposed) return;
        panel.webview.postMessage({ type: 'hubPrefillAiPrompt', prompt: pendingAiPrompt });
        pendingAiPrompt = '';
      }, 500);
    }
    return panel;
  };
}

module.exports = { createHub };
