// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file hub/actions.ts
 * @brief Handlers UI/misc, disasm, export, scan, rules, compilation, trace init, settings.
 *        Extracted from onDidReceiveMessage in hub.ts.
 */

const crypto = require('crypto');
const cp = require('child_process');
const { readArchSupportFromMapping } = require('./archSupport');

function createActions({
  panel,
  context,
  vscode,
  root,
  logChannel,
  fs,
  path,
  storageDir,
  globalDir,
  runPythonJson,
  runPythonJsonFile,
  resolvePathFromWorkspace,
  toWebviewPath,
  analysisCtx,
  handlers,
  compileCSource,
  payloadToHex,
  buildCmpPayloadSuggestion,
  isSupportedBinary,
  inspectBinaryInput,
  getRulesManagerScript,
  getSearchScript,
  getPayloadScriptRunnerScript,
  getExampleCandidates,
  SETTINGS_DEFAULTS,
  setSidebarMode,
  refreshSidebar,
  normalizePayloadTargetMode,
  payloadTargetLabel,
  resolvePayloadTarget,
  preferredMainSymbol,
  findSymbolByCandidates,
  mainSymbolCandidates,
}) {
  // ── Internal helpers ────────────────────────────────────────────────────────

  const hubPost = (type, data) => panel.webview.postMessage(Object.assign({ type }, data || {}));
  const hostMemorySnapshot = () => {
    const mem = process.memoryUsage();
    return {
      rss: mem.rss,
      heapUsed: mem.heapUsed,
      heapTotal: mem.heapTotal,
      external: mem.external,
      arrayBuffers: mem.arrayBuffers,
    };
  };
  const perfDiagnosticsEnabled = () => {
    try {
      return Boolean(vscode.workspace.getConfiguration?.('pileOuFace')?.get?.('perfDiagnostics', false));
    } catch (_) {
      return false;
    }
  };

  const finalizeDisasmOpen = async ({
    disasmPath,
    pathForWebview,
    binaryMeta,
    mappingPath = null,
    openInEditor = true,
    notifyWebview = true,
  }) => {
    if (!fs.existsSync(disasmPath)) {
      throw new Error(`Le backend n'a pas généré ${path.basename(disasmPath)}.`);
    }
    if (openInEditor) {
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(disasmPath));
      await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.One, preview: false });
    }
    if (notifyWebview) {
      const archPayload = readArchSupportFromMapping(mappingPath, fs);
      panel.webview.postMessage({
        type: 'hubSetBinaryPath',
        binaryPath: pathForWebview,
        binaryMeta,
        skipAutoLoad: true,
      });
      panel.webview.postMessage({
        type: 'hubDisasmReady',
        binaryPath: pathForWebview,
        arch: archPayload,
      });
    }
    if (refreshSidebar) refreshSidebar(pathForWebview);
  };

  const resolveDisasmMappingContext = async ({
    binaryPath,
    binaryMeta = null,
    logPrefix = 'Mapping',
  }) => {
    const ctx = analysisCtx.buildAnalysisArtifactContext(binaryPath, binaryMeta);
    const { tempDir, artifacts, baseName } = ctx;
    let { mappingPath, effectiveAbsPath } = ctx;
    ({ mappingPath, effectiveAbsPath } = analysisCtx.resolveLegacyArtifactFallback({
      tempDir,
      mappingPath,
      effectiveAbsPath,
      logPrefix,
    }));
    if (!fs.existsSync(mappingPath) && effectiveAbsPath) {
      ({ mappingPath } = await analysisCtx.ensureAnalysisMappingArtifacts({
        binaryPath: effectiveAbsPath,
        artifacts,
        mappingPath,
        useCacheDb: artifacts?.binaryMeta?.kind !== 'raw',
      }));
    }
    const mapping = analysisCtx.loadDisasmMapping(mappingPath);
    const disasmPath = mapping.path || artifacts?.disasmPath || path.join(tempDir, `${baseName}.disasm.asm`);
    return {
      ...ctx,
      effectiveAbsPath,
      mappingPath,
      mapping,
      disasmPath,
    };
  };

  const ensureMappingForBinary = async (binaryPath, binaryMeta = null) => {
    const { mapping } = await resolveDisasmMappingContext({
      binaryPath,
      binaryMeta,
      logPrefix: 'Mapping',
    });
    return mapping;
  };

  // ── Rules helpers ────────────────────────────────────────────────────────────

  const getRulesConfigPath = () => path.join(globalDir || context.globalStorageUri?.fsPath || '', 'rules-config.json');

  const ensureRulesStateDir = () => {
    const dir = globalDir || storageDir;
    fs.mkdirSync(dir, { recursive: true });
    return dir;
  };

  const runRulesManagerJson = (args, options = {}) => runPythonJsonFile(
    [
      getRulesManagerScript(root),
      ...args,
      '--cwd',
      root,
      '--global-config',
      getRulesConfigPath(),
    ],
    {
      timeout: 10000,
      maxBuffer: 512 * 1024,
      ...options,
    },
  );

  const postRulesState = async () => {
    const data = await runRulesManagerJson(['list']);
    const rules = Array.isArray(data.rules) ? data.rules : [];
    const activeYaraRules = rules.filter((rule) => rule.type === 'yara' && rule.enabled);
    hubPost('hubRulesList', {
      rules,
      error: data.error || null,
      activeYaraCount: activeYaraRules.length,
    });
  };

  // ── YARA helpers ─────────────────────────────────────────────────────────────

  const collectYaraFilesFromTarget = (targetPath) => {
    if (!targetPath || !fs.existsSync(targetPath)) return [];
    const stat = fs.statSync(targetPath);
    if (stat.isFile()) {
      return /\.(yar|yara)$/i.test(targetPath) ? [targetPath] : [];
    }
    if (!stat.isDirectory()) return [];
    const files = [];
    const stack = [targetPath];
    while (stack.length) {
      const current = stack.pop();
      let entries = [];
      try {
        entries = fs.readdirSync(current, { withFileTypes: true });
      } catch (_) {
        entries = [];
      }
      entries.forEach((entry) => {
        const fullPath = path.join(current, entry.name);
        if (entry.isDirectory()) {
          stack.push(fullPath);
          return;
        }
        if (entry.isFile() && /\.(yar|yara)$/i.test(entry.name)) {
          files.push(fullPath);
        }
      });
    }
    return files.sort();
  };

  const buildStagedYaraBundle = (label, sourcePaths) => {
    const resolvedFiles = [];
    sourcePaths.forEach((sourcePath) => {
      collectYaraFilesFromTarget(sourcePath).forEach((filePath) => {
        if (!resolvedFiles.includes(filePath)) resolvedFiles.push(filePath);
      });
    });
    if (!resolvedFiles.length) {
      throw new Error('Aucune règle YARA exploitable trouvée.');
    }
    if (resolvedFiles.length === 1 && fs.statSync(resolvedFiles[0]).isFile()) {
      return resolvedFiles[0];
    }
    const bundleRoot = path.join(
      ensureRulesStateDir(),
      'resolved-yara',
      crypto.createHash('sha1').update(root).digest('hex').slice(0, 12),
      label,
    );
    fs.rmSync(bundleRoot, { recursive: true, force: true });
    fs.mkdirSync(bundleRoot, { recursive: true });
    resolvedFiles.forEach((filePath, index) => {
      const baseName = path.basename(filePath).replace(/[^a-zA-Z0-9._-]+/g, '_');
      const targetName = `${String(index + 1).padStart(2, '0')}__${baseName}`;
      fs.copyFileSync(filePath, path.join(bundleRoot, targetName));
    });
    return bundleRoot;
  };

  const resolveManagedYaraTarget = async () => {
    const data = await runRulesManagerJson(['list']);
    const activePaths = (Array.isArray(data.rules) ? data.rules : [])
      .filter((rule) => rule.type === 'yara' && rule.enabled && rule.path)
      .map((rule) => String(rule.path).trim())
      .filter(Boolean);
    if (!activePaths.length) {
      // Fallback: dossier rules/yara/ à la racine du workspace s'il existe
      const defaultDir = path.join(root, 'rules', 'yara');
      if (fs.existsSync(defaultDir)) {
        return buildStagedYaraBundle('library-default', [defaultDir]);
      }
      throw new Error('Aucune règle YARA activée. Activez-en une ou configurez une bibliothèque globale.');
    }
    return buildStagedYaraBundle('library', activePaths);
  };

  const resolveYaraRulesTarget = async ({ mode, rulesPath }) => {
    const normalizedMode = String(mode || 'library').trim().toLowerCase();
    if (normalizedMode === 'library') {
      return resolveManagedYaraTarget();
    }
    const manualPath = String(rulesPath || '').trim();
    if (!manualPath) {
      throw new Error('Aucun chemin de règles YARA fourni.');
    }
    const absRules = path.isAbsolute(manualPath) ? manualPath : path.join(root, manualPath);
    if (!fs.existsSync(absRules)) {
      throw new Error('Fichier de règles introuvable.');
    }
    return absRules;
  };

  // ── Trace init helpers ───────────────────────────────────────────────────────

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
      payloadTargetReason: resolved.reason,
    };
  };

  const loadLatestTrace = () => {
    try {
      const outputJsonPath = path.join(storageDir, 'output.json');
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
          stopSymbol: '',
        },
      };
    }

    const info = await analysisCtx.loadBinaryHeaders(absoluteBinaryPath).catch(() => ({}));
    const symbols = await analysisCtx.loadBinarySymbols(absoluteBinaryPath);
    const inputSymbols = await analysisCtx.loadBinarySymbols(absoluteBinaryPath, { includeAll: true });
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
      stopSymbol: stopDefault,
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
      ...(typeof preset?.payloadExpr === 'string' ? { argvPayload: preset.payloadExpr } : {}),
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
      binarySymbols: inputSymbols,
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
      mvpProfile: mergedProfile,
    };
  };

  // ── Handlers ─────────────────────────────────────────────────────────────────

  return {
    hubModeChange: async (message) => {
      if (setSidebarMode) setSidebarMode(message.mode || 'other');
    },

    hubDebugLog: async (message) => {
      const rawScope = String(message.scope || 'webview');
      const scope = rawScope.replace(/[^a-z0-9_.:-]/gi, '_');
      const event = String(message.event || 'event').replace(/[^a-z0-9_.:-]/gi, '_');
      const details = message.details && typeof message.details === 'object' ? message.details : {};
      if (rawScope === 'perf.webview' && !perfDiagnosticsEnabled()) return;
      const enriched = rawScope === 'perf.webview'
        ? { ...details, extensionHostMemory: hostMemorySnapshot() }
        : details;
      logChannel.appendLine(`[${scope}] ${event} ${JSON.stringify(enriched)}`);
    },

    hubInstallDecompiler: async (message) => {
      const tool = message.tool || '';
      const platform = process.platform;
      const pm = platform === 'linux' ? (() => {
        for (const p of ['apt', 'dnf', 'pacman', 'zypper']) {
          const r = cp.spawnSync('which', [p], { stdio: 'pipe', timeout: 2000 });
          if (r.status === 0) return p;
        }
        return null;
      })() : null;

      const LABELS = {
        ghidra: 'Ghidra headless',
      };
      const INSTALL_LINES = {
        ghidra: [
          'macOS :  brew install ghidra && brew install openjdk@21',
          'Windows: winget install NationalSecurityAgency.Ghidra && winget install EclipseAdoptium.Temurin.21.JDK',
          'Linux  :  téléchargement manuel → https://ghidra-sre.org',
        ],
      };

      const label = LABELS[tool] || tool;
      const lines = INSTALL_LINES[tool] || [
        'Décompilateur custom : ajoutez une entrée dans storageUri/decompilers.json.',
        'Format : {"decompilers":{"mon-outil":{"command":["mon-outil","--binary","{binary}","--addr","{addr}"]}}}',
        'Fallback Docker : make decompilers-docker-build puis relancez la décompilation.',
      ];
      const detail = lines.join('\n');

      let installCmd = null;
      if (tool === 'ghidra') {
        if (platform === 'darwin') installCmd = 'brew install ghidra && brew install openjdk@21';
        else if (platform === 'win32') installCmd = 'winget install NationalSecurityAgency.Ghidra && winget install EclipseAdoptium.Temurin.21.JDK';
      }
      if (!installCmd && !LABELS[tool]) {
        installCmd = 'make decompilers-docker-build';
      }

      const buttons = installCmd ? ['Copier la commande', 'Annuler'] : (tool === 'ghidra' ? ['Ouvrir ghidra-sre.org', 'Annuler'] : ['Annuler']);
      const answer = await vscode.window.showInformationMessage(
        `${label} n'est pas installé`,
        { modal: true, detail },
        ...buttons
      );
      if (answer === 'Copier la commande' && installCmd) {
        await vscode.env.clipboard.writeText(installCmd);
        vscode.window.showInformationMessage(`Commande copiée : ${installCmd}`);
      } else if (answer === 'Ouvrir ghidra-sre.org') {
        vscode.env.openExternal(vscode.Uri.parse('https://ghidra-sre.org/'));
      }
    },

    staticOpen: async (message) => {
      const {
        binaryPath,
        absPath,
        exists,
        isDirectory,
        binaryMeta,
      } = analysisCtx.resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
      if (!binaryPath || !exists || isDirectory) {
        await handlers.requestBinarySelection();
        return;
      }
      try {
        const { artifacts, pathForWebview } = await analysisCtx.ensureDisasmArtifacts({
          binaryPath: absPath,
          binaryMeta,
          emitProgress: true,
          progressTitle: `Désassemblage de ${path.basename(absPath)}`,
          useCacheDb: binaryMeta?.kind !== 'raw',
        });
        await finalizeDisasmOpen({
          disasmPath: artifacts.disasmPath,
          pathForWebview,
          binaryMeta: artifacts.binaryMeta,
          mappingPath: artifacts.mappingPath,
          openInEditor: true,
        });
      } catch (err) {
        vscode.window.showErrorMessage(`Static: ${err.message || err}`);
      }
    },

    hubExportDisasm: async (message) => {
      const {
        binaryPath,
        absPath,
        exists,
        isDirectory,
        binaryMeta,
      } = analysisCtx.resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
      const tempDir = storageDir;
      let disasmPath = null;
      let mappingPath = null;
      if (binaryPath && exists && !isDirectory) {
        const artifacts = analysisCtx.getArtifactPaths({ binaryPath: absPath, binaryMeta });
        disasmPath = artifacts.disasmPath;
        mappingPath = artifacts.mappingPath;
      }
      const fallback = analysisCtx.resolveLegacyArtifactFallback({
        tempDir,
        mappingPath,
        disasmPath,
        logPrefix: 'ExportDisasm',
      });
      disasmPath = fallback.disasmPath;
      if (!disasmPath || !fs.existsSync(disasmPath)) {
        vscode.window.showWarningMessage('Aucun désassemblage trouvé. Ouvrez d\'abord le désassemblage ou sélectionnez un binaire.');
        return;
      }
      const defaultName = path.basename(disasmPath, '.asm').replace('.disasm', '') + '.disasm.txt';
      const defaultPath = path.join(path.dirname(disasmPath), defaultName);
      vscode.window.showSaveDialog({
        title: 'Exporter le désassemblage',
        defaultUri: vscode.Uri.file(defaultPath),
        filters: { 'Texte': ['txt'], 'Tous': ['*'] },
      }).then(async (saveUri) => {
        if (!saveUri) return;
        try {
          const text = fs.readFileSync(disasmPath, 'utf8');
          await fs.promises.writeFile(saveUri.fsPath, text, 'utf8');
          vscode.window.showInformationMessage(`Exporté: ${path.basename(saveUri.fsPath)}`);
        } catch (err) {
          vscode.window.showErrorMessage(`Export échoué: ${err.message}`);
        }
      });
    },

    hubPayloadToHex: async (message) => {
      try {
        const hex = payloadToHex(message.payload || '');
        hubPost('hubPayloadHex', { hex });
      } catch (err) {
        hubPost('hubPayloadHex', { error: err.message });
      }
    },

    hubAutoFromCmp: async (message) => {
      const binaryPath = String(message.binaryPath || '').trim();
      const cmpAddr = String(message.cmpAddr || '').trim();
      if (!binaryPath) {
        hubPost('hubAutoFromCmpResult', { error: 'Binaire manquant.' });
        return;
      }
      if (!cmpAddr) {
        hubPost('hubAutoFromCmpResult', { error: 'Adresse CMP manquante.' });
        return;
      }
      try {
        const mapping = await ensureMappingForBinary(binaryPath);
        const suggestion = buildCmpPayloadSuggestion(mapping.lines || [], cmpAddr);
        hubPost('hubAutoFromCmpResult', suggestion);
      } catch (err) {
        hubPost('hubAutoFromCmpResult', { error: err.message || String(err) });
      }
    },

    hubOpenDisasm: async (message) => {
      const {
        binaryPath,
        absPath,
        exists,
        isDirectory,
        binaryMeta,
      } = analysisCtx.resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
      if (!exists || isDirectory) {
        vscode.window.showErrorMessage(`Binaire introuvable: ${absPath}`);
        return;
      }
      try {
        const section = (message.section || '').trim();
        const artifacts = analysisCtx.getArtifactPaths({
          binaryPath: absPath,
          section,
          binaryMeta,
        });
        const { disasmPath, mappingPath } = artifacts;
        const useCache = message.useCache !== false;
        const requestedArch = (typeof message.arch === 'string' ? message.arch.trim() : '') || null;
        const cacheEligible = artifacts.binaryMeta.kind !== 'raw'
          && !section
          && (message.syntax || 'intel') === 'intel'
          && !requestedArch;
        const cacheValid = useCache && cacheEligible && fs.existsSync(disasmPath) && fs.existsSync(mappingPath);
        if (!cacheValid) {
          const annotationsJsonPath = analysisCtx.getBinaryAnnotationsJsonPath(absPath);
          await analysisCtx.ensureDisasmArtifacts({
            binaryPath: absPath,
            binaryMeta: artifacts.binaryMeta,
            section,
            syntax: message.syntax || 'intel',
            annotationsJson: fs.existsSync(annotationsJsonPath) ? annotationsJsonPath : null,
            dwarfLines: artifacts.binaryMeta.kind !== 'raw',
            emitProgress: true,
            progressTitle: `Désassemblage de ${path.basename(absPath)}`,
            useCacheDb: cacheEligible,
            cacheWriteOnly: !useCache,
            forceRebuild: !useCache,
          });
        } else {
          logChannel.appendLine(`[cache] Réutilisation de ${disasmPath}`);
        }
        const pathForWebview = path.relative(root, absPath).startsWith('..') ? absPath : path.relative(root, absPath);
        await finalizeDisasmOpen({
          disasmPath,
          pathForWebview,
          binaryMeta: artifacts.binaryMeta,
          mappingPath: artifacts.mappingPath,
          openInEditor: message.openInEditor !== false,
          notifyWebview: !section,
        });
      } catch (err) {
        vscode.window.showErrorMessage(`Désassemblage: ${err.message}`);
      }
    },

    hubSearchBinary: async (message) => {
      const {
        binaryPath,
        absPath,
        exists,
        isDirectory,
        binaryMeta,
      } = analysisCtx.resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
      const artifacts = binaryPath ? analysisCtx.getArtifactPaths({ binaryPath: absPath, binaryMeta }) : null;
      const pattern = (message.pattern || '').trim();
      const mode = message.mode || 'text';
      const section = (message.section || '').trim() || null;
      if (!exists || isDirectory || !pattern) {
        hubPost('hubRecherche', { results: [], error: 'Binaire ou motif manquant.' });
        return;
      }
      const args = [getSearchScript(root), '--binary', absPath, '--pattern', pattern, '--mode', mode];
      if (section) args.push('--section', section);
      if (artifacts?.binaryMeta?.kind === 'raw' && artifacts.binaryMeta.rawConfig?.baseAddr) {
        args.push('--raw-base-addr', String(artifacts.binaryMeta.rawConfig.baseAddr));
      }
      if (message.minLength != null) args.push('--min-length', String(message.minLength));
      if (message.maxLength != null) args.push('--max-length', String(message.maxLength));
      if (message.caseSensitive === false) args.push('--case-insensitive');
      if (message.offsetStart != null) args.push('--offset-start', String(message.offsetStart));
      if (message.offsetEnd != null) args.push('--offset-end', String(message.offsetEnd));
      try {
        const data = await runPythonJsonFile(args, { timeout: 30000, maxBuffer: 1024 * 1024, fallback: '[]' });
        const results = Array.isArray(data) ? data : (data.results || []);
        hubPost('hubRecherche', { results });
      } catch (err) {
        const stderr = String(err.stderr || '').trim();
        hubPost('hubRecherche', { results: [], error: stderr || err.message || 'Recherche échouée.' });
      }
    },

    hubListRules: async (_message) => {
      try {
        await postRulesState();
      } catch (err) {
        hubPost('hubRulesList', { rules: [], error: err.message });
      }
    },

    hubToggleRule: async (message) => {
      const { ruleId, enabled } = message;
      try {
        const data = await runRulesManagerJson(
          ['toggle', '--rule-id', ruleId, '--enabled', enabled ? 'true' : 'false'],
          { timeout: 5000 },
        );
        hubPost('hubRuleToggled', data);
      } catch (err) {
        hubPost('hubRuleToggled', { success: false, error: err.message });
      }
    },

    hubBrowseImportRule: async (message) => {
      const ruleType = String(message.ruleType || 'yara').toLowerCase();
      const scope = String(message.scope || 'global');
      const isYara = ruleType === 'yara';
      const picked = await vscode.window.showOpenDialog({
        canSelectMany: true,
        title: `Importer des règles ${ruleType.toUpperCase()}`,
        filters: isYara
          ? { 'YARA Rules': ['yar', 'yara'] }
          : { 'CAPA Rules': ['yml', 'yaml'] },
      });
      if (!picked?.length) {
        hubPost('hubRuleImported', { results: [] });
        return;
      }
      const results: { name: string; ok: boolean; error?: string }[] = [];
      for (const uri of picked) {
        const name = path.basename(uri.fsPath);
        try {
          const content = fs.readFileSync(uri.fsPath, 'utf8');
          await runRulesManagerJson(
            ['add', '--name', name, '--type', ruleType, '--content', content, '--scope', scope],
            { timeout: 5000 },
          );
          results.push({ name, ok: true });
        } catch (err) {
          results.push({ name, ok: false, error: (err as Error).message });
        }
      }
      await postRulesState();
      hubPost('hubRuleImported', { results });
    },

    hubAddUserRule: async (message) => {
      const { name, ruleType, content, scope } = message;
      try {
        const data = await runRulesManagerJson(
          ['add', '--name', name, '--type', ruleType, '--content', content, '--scope', scope || 'global'],
          { timeout: 5000 },
        );
        hubPost('hubRuleAdded', data);
      } catch (err) {
        hubPost('hubRuleAdded', { error: (err as Error).message });
      }
    },

    hubGetRuleContent: async (message) => {
      try {
        const data = await runRulesManagerJson(
          ['get', '--rule-id', message.ruleId],
          { timeout: 5000 },
        );
        hubPost('hubRuleContent', { rule: data.rule || null, error: data.error || null });
      } catch (err) {
        hubPost('hubRuleContent', { rule: null, error: err.message });
      }
    },

    hubUpdateUserRule: async (message) => {
      const { ruleId, name, content } = message;
      try {
        const data = await runRulesManagerJson(
          ['update', '--rule-id', ruleId, '--name', name, '--content', content],
          { timeout: 5000 },
        );
        hubPost('hubRuleUpdated', data);
      } catch (err) {
        hubPost('hubRuleUpdated', { error: err.message });
      }
    },

    hubDeleteUserRule: async (message) => {
      const { ruleId } = message;
      try {
        const data = await runRulesManagerJson(
          ['delete', '--rule-id', ruleId],
          { timeout: 5000 },
        );
        hubPost('hubRuleDeleted', data);
      } catch (err) {
        hubPost('hubRuleDeleted', { success: false, error: err.message });
      }
    },

    hubCompileStaticBinary: async (message) => {
      const sourcePath     = String(message.sourcePath || '').trim();
      const binaryPath     = String(message.binaryPath || '').trim();
      const archBits       = String(message.archBits || '64');
      const pieChoice      = String(message.pieChoice || 'no');
      const useLegacyFlags = message.useLegacyFlags === true;
      const optim          = useLegacyFlags ? null : String(message.optim || '-O0');
      const debug          = useLegacyFlags ? null : String(message.debug ?? '-g');
      const canary         = useLegacyFlags ? null : String(message.canary || 'off');
      const execstack      = useLegacyFlags ? true  : (message.execstack !== false);
      const relro          = String(message.relro || 'off');
      const staticLink     = message.static === true;
      const strip          = message.strip === true;
      const extraFlags     = String(message.extraFlags || '').trim();
      try {
        const result = await compileCSource({
          sourcePath,
          binaryPath,
          archBits,
          pieChoice,
          useLegacyFlags,
          includeExecstack: useLegacyFlags,
          optim,
          debug,
          canary,
          execstack,
          relro,
          staticLink,
          strip,
          extraFlags,
        });
        panel.webview.postMessage({
          type: 'hubSetBinaryPath',
          binaryPath: result.pathForWebview,
          binaryMeta: { kind: 'native', format: inspectBinaryInput(result.absoluteBinaryPath).format || '' },
        });
        if (refreshSidebar) refreshSidebar(result.pathForWebview);
        vscode.window.showInformationMessage(`Compilation OK: ${result.pathForWebview}`);
      } catch (err) {
        vscode.window.showErrorMessage(`Compilation échouée: ${err.message || err}`);
      } finally {
        panel.webview.postMessage({ type: 'hubStaticCompileDone' });
      }
    },

    hubSaveScript: async (message) => {
      const scriptsDir = path.join(storageDir, 'scripts');
      if (!fs.existsSync(scriptsDir)) fs.mkdirSync(scriptsDir, { recursive: true });
      const name = message.name || 'script.py';
      const filePath = path.join(scriptsDir, name);
      fs.writeFileSync(filePath, message.content, 'utf8');
      panel.webview.postMessage({ type: 'hubScriptSaved', path: filePath });
    },

    hubLoadScript: async (_message) => {
      const picked = await vscode.window.showOpenDialog({
        canSelectFiles: true, canSelectMany: false,
        filters: { 'Python': ['py'] },
        title: 'Charger un script Python',
        defaultUri: vscode.Uri.file(path.join(storageDir, 'scripts')),
      });
      if (picked && picked[0]) {
        const content = fs.readFileSync(picked[0].fsPath, 'utf8');
        const name = path.basename(picked[0].fsPath);
        panel.webview.postMessage({ type: 'hubScriptLoaded', content, name });
      }
    },

    hubLoadPwntoolsScript: async (_message) => {
      const picked = await vscode.window.showOpenDialog({
        canSelectFiles: true,
        canSelectMany: false,
        filters: { 'Python': ['py'] },
        title: 'Importer un script pwntools',
        defaultUri: vscode.Uri.file(root),
      });
      if (picked && picked[0]) {
        const filePath = picked[0].fsPath;
        const content = fs.readFileSync(filePath, 'utf8');
        panel.webview.postMessage({
          type: 'hubPwntoolsScriptLoaded',
          content,
          path: filePath,
          name: path.basename(filePath),
        });
      }
    },

    hubAnalyzePwntoolsScript: async (message) => {
      const scriptContent = String(message.scriptContent || '');
      const sourceFileName = String(message.sourceFileName || 'payload.py').trim() || 'payload.py';
      const scriptPathRaw = String(message.scriptPath || '').trim();
      const binaryPathRaw = String(message.binaryPath || '').trim();
      const resolvedScriptPath = scriptPathRaw ? resolvePathFromWorkspace(scriptPathRaw) : '';
      const resolvedBinaryPath = binaryPathRaw ? resolvePathFromWorkspace(binaryPathRaw) : '';
      const scriptRoot = resolvedScriptPath
        ? path.dirname(resolvedScriptPath)
        : (resolvedBinaryPath ? path.dirname(resolvedBinaryPath) : root);
      if (!scriptContent.trim()) {
        panel.webview.postMessage({
          type: 'hubPwntoolsScriptAnalyzed',
          result: {
            ok: false,
            sourceFileName,
            captures: [],
            captured: [],
            globals: {},
            processes: [],
            warnings: ['Script pwntools requis.'],
            error: 'Le script pwntools est vide.',
            stdout: '',
            stderr: '',
          },
        });
        return;
      }
      const tempDir = storageDir;
      const nonce = crypto.randomBytes(6).toString('hex');
      const tempScriptPath = path.join(tempDir, `pwntools-script-${nonce}.py`);
      fs.writeFileSync(tempScriptPath, scriptContent, 'utf8');
      let result = null;
      try {
        result = await runPythonJsonFile(
          [
            getPayloadScriptRunnerScript(root),
            '--script-file',
            tempScriptPath,
            '--source-name',
            sourceFileName,
            '--script-root',
            scriptRoot,
            '--timeout-seconds',
            '2.0',
            ...(resolvedBinaryPath ? ['--script-arg', resolvedBinaryPath] : []),
          ],
          {
            timeout: 3000,
            maxBuffer: 8 * 1024 * 1024,
          },
        );
      } catch (err) {
        result = {
          ok: false,
          sourceFileName,
          captures: [],
          captured: [],
          globals: {},
          processes: [],
          warnings: ['Analyse du script pwntools impossible.'],
          error: String(err?.stderr || err?.stdout || err?.message || err || 'Erreur inconnue'),
          stdout: String(err?.stdout || ''),
          stderr: String(err?.stderr || ''),
        };
      } finally {
        try {
          if (fs.existsSync(tempScriptPath)) fs.unlinkSync(tempScriptPath);
        } catch (_) {
          // ignore temp cleanup failures
        }
      }
      const capturesCount = Array.isArray(result?.captures)
        ? result.captures.length
        : (Array.isArray(result?.captured) ? result.captured.length : 0);
      logChannel.appendLine(`[payload] pwntools analysis source=${sourceFileName} ok=${result?.ok !== false} captures=${capturesCount}`);
      panel.webview.postMessage({ type: 'hubPwntoolsScriptAnalyzed', result });
    },

    hubPickFile: async (message) => {
      const isBinaryTarget = message.fileType === 'binary';
      const isSourceTarget = message.fileType === 'sourceC' || message.target === 'dynamicSourcePath';
      const dialogOpts = {
        canSelectFiles: true, canSelectMany: false,
        defaultUri: vscode.Uri.file(root),
      };
      if (isBinaryTarget) {
        dialogOpts.title = 'Sélectionner un binaire (ELF, Mach-O, PE)';
        dialogOpts.filters = { 'Tous les fichiers': ['*'] };
      } else if (isSourceTarget) {
        dialogOpts.title = 'Sélectionner un fichier source C';
        dialogOpts.filters = { 'Source C': ['c', 'h'], 'Tous les fichiers': ['*'] };
      } else {
        dialogOpts.title = 'Sélectionner un fichier';
      }
      const picked = await vscode.window.showOpenDialog(dialogOpts);
      if (picked && picked[0]) {
        if (isBinaryTarget && !isSupportedBinary(picked[0].fsPath)) {
          vscode.window.showErrorMessage('Format non supporté — sélectionnez un binaire ELF, Mach-O ou PE.');
          return;
        }
        panel.webview.postMessage({ type: 'hubPickedFile', target: message.target, path: picked[0].fsPath });
      }
    },

    requestRunTraceInit: async (message) => {
      const initPayload = await buildRunTraceInit(
        message.binaryPath || '',
        message.preset || null,
        message.sourcePath || '',
        message.payloadTargetMode || 'auto'
      );
      panel.webview.postMessage({ type: 'initRunTrace', ...initPayload });
    },

    readyRunTrace: async (_message) => {
      const initPayload = await buildRunTraceInit();
      panel.webview.postMessage({ type: 'initRunTrace', ...initPayload });
    },

    refreshRunTraceBinary: async (message) => {
      const initPayload = await buildRunTraceInit(
        message.binaryPath || '',
        null,
        message.sourcePath || '',
        message.payloadTargetMode || 'auto'
      );
      panel.webview.postMessage({ type: 'initRunTrace', ...initPayload });
    },

    selectRunTraceBinary: async (message) => {
      const binaryUri = await vscode.window.showOpenDialog({
        title: 'Pile ou Face — Sélectionner le binaire du projet',
        defaultUri: vscode.Uri.file(root),
        canSelectMany: false,
        filters: { 'Binaires': ['elf', 'out', 'bin'], 'Tous': ['*'] },
      });
      if (!binaryUri?.length) return;
      const binaryPath = binaryUri[0].fsPath;
      const pathForWebview = toWebviewPath(binaryPath);
      panel.webview.postMessage({ type: 'hubSetBinaryPath', binaryPath: pathForWebview });
      const initPayload = await buildRunTraceInit(pathForWebview, null, message.sourcePath || '', message.payloadTargetMode || 'auto');
      panel.webview.postMessage({ type: 'initRunTrace', ...initPayload });
      if (refreshSidebar) refreshSidebar(pathForWebview);
    },

    hubGetSettings: async (_message) => {
      const settings = context.globalState.get('pof-settings', SETTINGS_DEFAULTS);
      panel.webview.postMessage({ type: 'hubSettings', settings: { ...SETTINGS_DEFAULTS, ...settings } });
    },

    hubSaveSettings: async (message) => {
      await context.globalState.update('pof-settings', message.settings);
      panel.webview.postMessage({ type: 'hubSettingsSaved', ok: true });
    },

    hubResetSettings: async (_message) => {
      await context.globalState.update('pof-settings', SETTINGS_DEFAULTS);
      panel.webview.postMessage({ type: 'hubSettings', settings: { ...SETTINGS_DEFAULTS } });
    },
  };
}

module.exports = { createActions };
