// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck

const { getExtensionPath } = require('../../shared/utils');
const { makeMappingStore } = require('../../shared/mappingStore');

function createAnalysisContext({
  root,
  pythonExe,
  logChannel,
  runCommand,
  runPythonJson,
  runPythonTextFile,
  resolvePathFromWorkspace,
  toWebviewPath,
  storageDir,
  ensureTempDir,
  getRawProfile,
  vscode,
  fs,
  path,
  crypto,
  inspectBinaryInput,
  normalizeRawProfile,
  getRawArchDescriptor,
  readCache,
  writeCache,
  getDisasmScript,
  getHeadersScript,
  getSymbolsScript,
  getOffsetToVaddrScript,
  getDiscoverFunctionsScript,
  getExampleCandidates,
  normalizeAddress,
}) {
  // In-flight deduplication: concurrent callers for the same disasmPath share one subprocess.
  const _disasmInFlight = new Map<string, Promise<void>>();

  const sanitizeArtifactToken = (value, fallback = 'item') => {
    const text = String(value || '').trim();
    const safe = text.replace(/[^a-zA-Z0-9._-]/g, '_').replace(/_+/g, '_');
    return safe || fallback;
  };

  const getDisasmCacheDbPath = (binaryPath) => {
    if (!storageDir) return 'auto';
    const absPath = resolvePathFromWorkspace(binaryPath);
    const cacheDir = path.join(storageDir, 'pfdb');
    fs.mkdirSync(cacheDir, { recursive: true });
    const cacheName = sanitizeArtifactToken(path.basename(absPath), 'binary');
    const cacheKey = crypto.createHash('sha256').update(String(path.resolve(absPath))).digest('hex').slice(0, 16);
    return path.join(cacheDir, `${cacheName}.${cacheKey}.pfdb`);
  };

  const getBinaryRuntimeProfile = (binaryPath, messageMeta = null) => {
    const absPath = resolvePathFromWorkspace(binaryPath);
    const explicit = normalizeRawProfile(messageMeta?.rawConfig || messageMeta);
    const stored = getRawProfile(absPath);
    const rawProfile = explicit || stored;
    const inspection = inspectBinaryInput(absPath);
    if (rawProfile && !inspection.supported) {
      return {
        kind: 'raw',
        format: 'RAW',
        arch: rawProfile.arch,
        rawConfig: rawProfile,
      };
    }
    return {
      kind: 'native',
      format: inspection.format || '',
      arch: '',
      rawConfig: null,
    };
  };

  const getArtifactPaths = ({ binaryPath, section = '', binaryMeta = null }) => {
    const absPath = resolvePathFromWorkspace(binaryPath);
    const profile = getBinaryRuntimeProfile(absPath, binaryMeta);
    const tempDir = storageDir || (ensureTempDir ? ensureTempDir(root) : '');
    const baseName = path.basename(absPath, path.extname(absPath)) || 'binary';
    const rawSuffix = profile.kind === 'raw'
      ? `.raw.${sanitizeArtifactToken(profile.rawConfig?.arch, 'raw')}.${sanitizeArtifactToken(profile.rawConfig?.endian || 'little')}.${sanitizeArtifactToken(String(profile.rawConfig?.baseAddr || '0x0').replace(/^0x/i, '0x'))}`
      : '';
    const sectionSuffix = section ? `.section.${sanitizeArtifactToken(section)}` : '';
    const stem = `${baseName}${rawSuffix}${sectionSuffix}`;
    return {
      absPath,
      binaryMeta: profile,
      stem,
      disasmPath: path.join(tempDir, `${stem}.disasm.asm`),
      mappingPath: path.join(tempDir, `${stem}.disasm.mapping.json`),
      discoveredPath: path.join(tempDir, `${stem}.discovered.json`),
      symbolsPath: path.join(tempDir, `${stem}.symbols.json`),
      tempDir,
    };
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

  const resolveArtifactBinaryPath = (inputPath) => {
    const requestedPath = String(inputPath || '').trim();
    if (!requestedPath) return '';
    const absRequestedPath = resolvePathFromWorkspace(requestedPath);
    if (!absRequestedPath || !fs.existsSync(absRequestedPath)) return absRequestedPath;
    const fileName = path.basename(absRequestedPath);
    const isArtifact = (
      fileName.endsWith('.disasm.asm')
      || fileName.endsWith('.disasm.mapping.json')
      || fileName.endsWith('.symbols.json')
      || fileName.endsWith('.discovered.json')
    );
    if (!isArtifact) return absRequestedPath;
    const mappingPath = fileName.endsWith('.disasm.mapping.json')
      ? absRequestedPath
      : absRequestedPath
        .replace(/\.disasm\.asm$/i, '.disasm.mapping.json')
        .replace(/\.symbols\.json$/i, '.disasm.mapping.json')
        .replace(/\.discovered\.json$/i, '.disasm.mapping.json');
    if (!fs.existsSync(mappingPath)) return absRequestedPath;
    try {
      const mapping = JSON.parse(fs.readFileSync(mappingPath, 'utf8'));
      const binary = String(mapping?.binary || '').trim();
      if (!binary) return absRequestedPath;
      const resolvedBinary = path.isAbsolute(binary)
        ? binary
        : path.resolve(path.dirname(mappingPath), binary);
      return fs.existsSync(resolvedBinary) ? resolvedBinary : absRequestedPath;
    } catch (_) {
      return absRequestedPath;
    }
  };

  const resolveBinaryInputContext = (binaryPath, binaryMeta = null) => {
    const requestedPath = String(binaryPath || '').trim();
    const absPath = requestedPath ? resolveArtifactBinaryPath(requestedPath) : '';
    const exists = !!absPath && fs.existsSync(absPath);
    let isDirectory = false;
    if (exists) {
      try {
        isDirectory = fs.statSync(absPath).isDirectory();
      } catch (_) {
        isDirectory = false;
      }
    }
    return {
      binaryPath: requestedPath,
      absPath,
      exists,
      isDirectory,
      binaryMeta: requestedPath ? getBinaryRuntimeProfile(absPath, binaryMeta) : null,
    };
  };

  const buildDisasmArgs = ({
    binaryPath,
    disasmPath,
    mappingPath,
    syntax = null,
    section = null,
    arch = null,
    rawArch = null,
    rawBaseAddr = null,
    rawEndian = null,
    annotationsJson = null,
    dwarfLines = false,
    useCacheDb = false,
    cacheWriteOnly = false,
    emitProgress = false,
  }) => {
    const args = [
      getDisasmScript(root),
      '--binary',
      binaryPath,
      '--output',
      disasmPath,
      '--output-mapping',
      mappingPath,
    ];
    if (syntax) args.push('--syntax', syntax);
    if (annotationsJson) args.push('--annotations-json', annotationsJson);
    if (section) args.push('--section', section);
    if (arch) args.push('--arch', arch);
    if (rawArch) args.push('--raw-arch', rawArch);
    if (rawBaseAddr) args.push('--raw-base-addr', rawBaseAddr);
    if (rawEndian) args.push('--raw-endian', rawEndian);
    if (dwarfLines) args.push('--dwarf-lines');
    if (useCacheDb) args.push('--cache-db', typeof useCacheDb === 'string' ? useCacheDb : getDisasmCacheDbPath(binaryPath));
    if (cacheWriteOnly) args.push('--cache-write-only');
    if (emitProgress) args.push('--progress');
    return args;
  };

  const createDisasmProgressHandler = (progress) => {
    let buffer = '';
    let lastPercent = 0;
    return {
      hook(chunk) {
        buffer += String(chunk || '');
        const lines = buffer.split(/\r?\n/);
        buffer = lines.pop() || '';
        const passthrough = [];
        for (const line of lines) {
          if (line.startsWith('POF_PROGRESS ')) {
            try {
              const payload = JSON.parse(line.slice('POF_PROGRESS '.length));
              const nextPercent = Math.max(
                lastPercent,
                Math.min(100, Number(payload.percent || 0))
              );
              progress.report({
                increment: nextPercent - lastPercent,
                message: payload.message || 'Analyse…',
              });
              lastPercent = nextPercent;
              continue;
            } catch (_) {
              // keep raw line in the log channel below
            }
          }
          passthrough.push(line);
        }
        return passthrough.length > 0 ? `${passthrough.join('\n')}\n` : false;
      },
      finish(message = 'Terminé') {
        if (lastPercent < 100) {
          progress.report({ increment: 100 - lastPercent, message });
          lastPercent = 100;
        }
      },
    };
  };

  const runDisasmWithProgress = async (title, args) => {
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title,
        cancellable: true,
      },
      async (progress, token) => {
        progress.report({ increment: 0, message: 'Initialisation…' });
        const progressHandler = createDisasmProgressHandler(progress);
        token?.onCancellationRequested?.(() => {
          progress.report({ increment: 0, message: 'Annulation…' });
        });
        await runCommand(
          pythonExe,
          args,
          root,
          logChannel,
          { PYTHONPATH: getExtensionPath() || root },
          { onStderrData: progressHandler.hook, cancelToken: token }
        );
        progressHandler.finish();
      }
    );
  };

  const loadBinaryHeaders = async (binaryPath, { useCache = true } = {}) => {
    const cached = readAnalysisCacheEntry(binaryPath, useCache, 'info');
    if (cached && typeof cached === 'object') {
      logChannel?.appendLine?.('[cache] Infos binaire depuis cache');
      return cached;
    }
    const info = await runPythonJson(getHeadersScript(root), ['--binary', binaryPath]);
    writeAnalysisCacheEntry(binaryPath, useCache, 'info', info);
    return info;
  };

  const ensureDisasmArtifacts = async ({
    binaryPath,
    binaryMeta = null,
    section = '',
    syntax = 'intel',
    annotationsJson = null,
    dwarfLines = false,
    emitProgress = false,
    progressTitle = '',
    useCacheDb = null,
    cacheWriteOnly = false,
    forceRebuild = false,
  }) => {
    const absPath = resolvePathFromWorkspace(binaryPath);
    if (!fs.existsSync(absPath) || fs.statSync(absPath).isDirectory()) {
      throw new Error(`Binaire introuvable: ${absPath}`);
    }
    const artifacts = getArtifactPaths({ binaryPath: absPath, section, binaryMeta });
    const shouldUseCacheDb = useCacheDb !== null
      ? useCacheDb
      : (artifacts.binaryMeta.kind !== 'raw' && !section && syntax === 'intel');
    if (forceRebuild || !fs.existsSync(artifacts.disasmPath) || !fs.existsSync(artifacts.mappingPath)) {
      const inflightKey = artifacts.disasmPath;
      if (_disasmInFlight.has(inflightKey)) {
        await _disasmInFlight.get(inflightKey);
      } else {
        const runDisasm = async () => {
          // disasm.py auto-détecte l'architecture via lief (--arch est ignoré) :
          // ne pas bloquer le désassemblage sur headers.py, juste réchauffer le
          // cache d'infos binaire en parallèle pour les consommateurs suivants.
          const warmHeaders = artifacts.binaryMeta.kind !== 'raw'
            ? loadBinaryHeaders(absPath).catch(() => null)
            : null;
          const args = buildDisasmArgs({
            binaryPath: absPath,
            disasmPath: artifacts.disasmPath,
            mappingPath: artifacts.mappingPath,
            syntax,
            section,
            rawArch: artifacts.binaryMeta.rawConfig?.arch || null,
            rawBaseAddr: artifacts.binaryMeta.rawConfig?.baseAddr || null,
            rawEndian: artifacts.binaryMeta.rawConfig?.endian || null,
            annotationsJson,
            dwarfLines,
            useCacheDb: shouldUseCacheDb,
            cacheWriteOnly: cacheWriteOnly && !!shouldUseCacheDb,
            emitProgress,
          });
          if (emitProgress) {
            await runDisasmWithProgress(
              progressTitle || `Désassemblage de ${path.basename(absPath)}`,
              args,
            );
          } else {
            await runCommand(pythonExe, args, root, logChannel, { PYTHONPATH: getExtensionPath() || root });
          }
          if (warmHeaders) await warmHeaders;
        };
        const promise = runDisasm().finally(() => { _disasmInFlight.delete(inflightKey); });
        _disasmInFlight.set(inflightKey, promise);
        await promise;
      }
    }
    return {
      absPath,
      artifacts,
      pathForWebview: toWebviewPath(absPath),
    };
  };

  const resolveLegacyArtifactFallback = ({
    tempDir,
    mappingPath = null,
    disasmPath = null,
    symbolsPath = null,
    discoveredPath = null,
    effectiveAbsPath = null,
    logPrefix = 'Artifacts',
    exampleLimit = null,
  }) => {
    const current = {
      mappingPath,
      disasmPath,
      symbolsPath,
      discoveredPath,
      effectiveAbsPath,
    };
    if (current.mappingPath && fs.existsSync(current.mappingPath)) return current;
    if (!fs.existsSync(tempDir)) return current;
    const mappingFiles = fs.readdirSync(tempDir).filter((n) => n.endsWith('.disasm.mapping.json'));
    if (mappingFiles.length === 0) return current;

    const expectedBinaryPath = current.effectiveAbsPath
      ? path.resolve(resolvePathFromWorkspace(current.effectiveAbsPath))
      : '';
    const normalizeComparablePath = (value) => {
      const text = String(value || '').trim();
      if (!text) return '';
      return path.resolve(resolvePathFromWorkspace(text));
    };
    const fallbackName = mappingFiles.find((candidateName) => {
      if (!expectedBinaryPath) return true;
      const candidatePath = path.join(tempDir, candidateName);
      try {
        const mapping = JSON.parse(fs.readFileSync(candidatePath, 'utf8'));
        const mappedBinary = normalizeComparablePath(mapping?.binary);
        return !!mappedBinary && mappedBinary === expectedBinaryPath;
      } catch (_) {
        return false;
      }
    });
    if (!fallbackName) {
      logChannel.appendLine(`[${logPrefix}] Mapping fallback ignoré: aucun mapping ne correspond au binaire courant`);
      return current;
    }

    const fallbackBase = fallbackName.replace('.disasm.mapping.json', '');
    current.mappingPath = path.join(tempDir, fallbackName);
    if (current.disasmPath !== null) {
      try {
        const mapping = JSON.parse(fs.readFileSync(current.mappingPath, 'utf8'));
        current.disasmPath = mapping?.path || path.join(tempDir, `${fallbackBase}.disasm.asm`);
      } catch (_) {
        current.disasmPath = path.join(tempDir, `${fallbackBase}.disasm.asm`);
      }
    }
    if (current.symbolsPath !== null) {
      current.symbolsPath = path.join(tempDir, `${fallbackBase}.symbols.json`);
    }
    if (current.discoveredPath !== null) {
      current.discoveredPath = path.join(tempDir, `${fallbackBase}.discovered.json`);
    }
    if (current.effectiveAbsPath !== null) {
      const candidates = getExampleCandidates(root, fallbackBase);
      const limited = Number.isInteger(exampleLimit) ? candidates.slice(0, exampleLimit) : candidates;
      current.effectiveAbsPath = limited.find((p) => fs.existsSync(p) && !fs.statSync(p).isDirectory()) || current.effectiveAbsPath;
    }
    logChannel.appendLine(`[${logPrefix}] Mapping fallback: ${fallbackName}`);
    return current;
  };

  const buildAnalysisArtifactContext = (binaryPath, binaryMeta = null) => {
    const absPath = binaryPath ? path.resolve(root, binaryPath) : root;
    const tempDir = storageDir || (ensureTempDir ? ensureTempDir(root) : '');
    const hasFileBinary = !!binaryPath && fs.existsSync(absPath) && !fs.statSync(absPath).isDirectory();
    const artifacts = hasFileBinary
      ? getArtifactPaths({ binaryPath: absPath, binaryMeta })
      : null;
    const baseName = hasFileBinary ? path.basename(absPath, path.extname(absPath)) : 'binary';
    return {
      absPath,
      tempDir,
      artifacts,
      baseName,
      effectiveAbsPath: hasFileBinary ? absPath : null,
      mappingPath: artifacts?.mappingPath || path.join(tempDir, `${baseName}.disasm.mapping.json`),
      symbolsPath: artifacts?.symbolsPath || path.join(tempDir, `${baseName}.symbols.json`),
      discoveredPath: artifacts?.discoveredPath || path.join(tempDir, `${baseName}.discovered.json`),
    };
  };

  const getAnalysisCacheTarget = (effectiveAbsPath, allowCache) => {
    if (!allowCache || !effectiveAbsPath || !fs.existsSync(effectiveAbsPath)) return null;
    try {
      return fs.statSync(effectiveAbsPath).isDirectory() ? null : effectiveAbsPath;
    } catch (_) {
      return null;
    }
  };

  const readAnalysisCacheEntry = (effectiveAbsPath, allowCache, cacheKey) => {
    const target = getAnalysisCacheTarget(effectiveAbsPath, allowCache);
    if (!target) return null;
    return readCache(storageDir, target, cacheKey);
  };

  const writeAnalysisCacheEntry = (effectiveAbsPath, allowCache, cacheKey, value) => {
    const target = getAnalysisCacheTarget(effectiveAbsPath, allowCache);
    if (!target) return false;
    writeCache(storageDir, target, cacheKey, value);
    return true;
  };

  const resolveCachedAnalysisView = async ({
    effectiveAbsPath,
    allowCache,
    cacheKey,
    logLabel = null,
    compute,
  }) => {
    const cached = readAnalysisCacheEntry(effectiveAbsPath, allowCache, cacheKey);
    if (cached) {
      if (logLabel) logChannel.appendLine(`[cache] ${logLabel} depuis cache`);
      return cached;
    }
    const value = await compute();
    writeAnalysisCacheEntry(effectiveAbsPath, allowCache, cacheKey, value);
    return value;
  };

  const ensureAnalysisMappingArtifacts = async ({
    binaryPath,
    artifacts = null,
    mappingPath,
    symbolsPath = undefined,
    discoveredPath = undefined,
    useCacheDb = false,
    cacheWriteOnly = false,
  }) => {
    if (fs.existsSync(mappingPath)) {
      return { mappingPath, symbolsPath, discoveredPath };
    }
    const ensured = await ensureDisasmArtifacts({
      binaryPath,
      binaryMeta: artifacts?.binaryMeta || null,
      useCacheDb,
      cacheWriteOnly,
    });
    return {
      mappingPath: ensured.artifacts.mappingPath,
      symbolsPath: symbolsPath === undefined ? undefined : ensured.artifacts.symbolsPath,
      discoveredPath: discoveredPath === undefined ? undefined : ensured.artifacts.discoveredPath,
    };
  };

  const loadDisasmMapping = (mappingPath) => {
    if (!mappingPath || !fs.existsSync(mappingPath)) {
      throw new Error('Mapping désassemblage introuvable.');
    }
    // En-tête allégé : les lignes vivent dans le SQLite associé et se
    // requêtent via mappingStore. Un artefact legacy (avant migration)
    // porte encore `lines` — toléré tel quel.
    const mapping = JSON.parse(fs.readFileSync(mappingPath, 'utf8'));
    const legacyCount = Array.isArray(mapping?.lines) ? mapping.lines.length : 0;
    const lineCount = Number(mapping?.line_count || 0) || legacyCount;
    if (lineCount <= 0) {
      throw new Error('Mapping désassemblage vide.');
    }
    return mapping;
  };

  const getMappingEntrySpanLength = (entry) => {
    const rawBytes = String(entry?.bytes || '').trim();
    if (rawBytes) {
      const count = rawBytes.split(/\s+/).filter(Boolean).length;
      if (count > 0) return count;
    }
    const rawText = String(entry?.text || '');
    const match = rawText.match(/^\s*(?:0x[0-9a-fA-F]+)\s*:\s*([0-9a-fA-F ]+)/);
    if (match) {
      const count = String(match[1] || '')
        .trim()
        .split(/\s+/)
        .filter((part) => /^[0-9a-fA-F]{2}$/.test(part))
        .length;
      if (count > 0) return count;
    }
    return 1;
  };

  const findDisasmMappingEntryByAddress = (lines, addrInput) => {
    const target = normalizeAddress(addrInput);
    if (!target) return null;
    return lines.find((line) => normalizeAddress(line?.addr || '')?.value === target.value) || null;
  };

  const mappingStore = makeMappingStore({ runPythonJson });

  // Requêtes du mapping SQLite (node:sqlite, repli Python) — jamais de
  // chargement du mapping complet dans l'extension host.
  const findMappingEntryByAddr = (mappingPath, addr) =>
    mappingStore.findEntryByAddr(mappingPath, addr);
  const queryMappingWindow = (mappingPath, addr, limit) =>
    mappingStore.queryWindow(mappingPath, addr, limit);

  const openDisasmAtLine = async (disasmPath, lineNumber) => {
    if (!disasmPath || !fs.existsSync(disasmPath)) {
      throw new Error('Fichier de désassemblage introuvable.');
    }
    const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(disasmPath));
    const editor = await vscode.window.showTextDocument(doc, {
      viewColumn: vscode.ViewColumn.One,
      preview: false,
    });
    const targetLine = Math.max(0, Number(lineNumber || 1) - 1);
    const range = new vscode.Range(targetLine, 0, targetLine, 1000);
    editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
    editor.selection = new vscode.Selection(range.start, range.start);
    return { doc, editor };
  };

  const getBinaryAnnotationsJsonPath = (absPath) => {
    const hash = crypto
      .createHash('sha256')
      .update(absPath)
      .update(fs.existsSync(absPath) ? String(fs.statSync(absPath).mtimeMs) : '')
      .digest('hex')
      .slice(0, 16);
    const effectiveDir = storageDir || (ensureTempDir ? ensureTempDir(root) : '');
    return path.join(effectiveDir, 'annotations', `${hash}.json`);
  };

  const loadBinarySymbols = async (binaryPath, { includeAll = false, useCache = true } = {}) => {
    const cacheKey = includeAll ? 'symbols_all' : 'symbols';
    const cached = readAnalysisCacheEntry(binaryPath, useCache, cacheKey);
    if (Array.isArray(cached)) {
      logChannel?.appendLine?.(`[cache] Symboles depuis cache (${includeAll ? 'all' : 'default'})`);
      return cached;
    }
    const args = ['--binary', binaryPath];
    if (includeAll) args.push('--all');
    const rawSymbols = await runPythonJson(getSymbolsScript(root), args).catch(() => []);
    const symbols = Array.isArray(rawSymbols) ? rawSymbols : (rawSymbols.symbols || []);
    writeAnalysisCacheEntry(binaryPath, useCache, cacheKey, symbols);
    return symbols;
  };

  const collectSymbolNames = (symbols) => {
    const seen = new Set();
    const names = [];
    for (const symbol of symbols || []) {
      const name = String(symbol?.name || '').trim();
      if (!name || !/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name) || seen.has(name)) continue;
      seen.add(name);
      names.push(name);
    }
    names.sort();
    return names;
  };

  const loadOffsetToVaddr = async (binaryPath, fileOffset) => (
    runPythonTextFile([
      getOffsetToVaddrScript(root),
      '--binary',
      binaryPath,
      '--offset',
      String(fileOffset),
    ])
  );

  const ensureDiscoveredFunctionsArtifact = async ({
    artifacts,
    absPath,
    mappingPath,
    baseName,
  }) => {
    const effectiveDir = storageDir || (ensureTempDir ? ensureTempDir(root) : '');
    const discoveredPath = artifacts?.discoveredPath || path.join(effectiveDir, `${baseName}.discovered.json`);
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

  const resolveAnalysisArtifactsContext = async ({
    binaryPath,
    binaryMeta = null,
    logPrefix = 'Artifacts',
    exampleLimit = null,
    ensureMapping = false,
    useCache = true,
  }) => {
    const context = buildAnalysisArtifactContext(binaryPath, binaryMeta);
    const { absPath, tempDir, artifacts } = context;
    let {
      mappingPath,
      symbolsPath,
      discoveredPath,
      effectiveAbsPath,
    } = context;
    ({
      mappingPath,
      symbolsPath,
      discoveredPath,
      effectiveAbsPath,
    } = resolveLegacyArtifactFallback({
      tempDir,
      mappingPath,
      symbolsPath,
      discoveredPath,
      effectiveAbsPath,
      logPrefix,
      exampleLimit,
    }));
    const hasAnalyzableBinary = !!binaryPath
      && fs.existsSync(absPath)
      && !fs.statSync(absPath).isDirectory();
    const cacheDbEligible = !(artifacts?.binaryMeta?.kind === 'raw');
    const allowCache = useCache !== false && cacheDbEligible;
    if (ensureMapping && !fs.existsSync(mappingPath) && hasAnalyzableBinary) {
      ({
        mappingPath,
        symbolsPath,
        discoveredPath,
      } = await ensureAnalysisMappingArtifacts({
        binaryPath: absPath,
        artifacts,
        mappingPath,
        symbolsPath,
        discoveredPath,
        useCacheDb: cacheDbEligible,
        cacheWriteOnly: useCache === false,
      }));
    }
    return {
      ...context,
      mappingPath,
      symbolsPath,
      discoveredPath,
      effectiveAbsPath,
      allowCache,
      hasAnalyzableBinary,
    };
  };

  return {
    sanitizeArtifactToken,
    getBinaryRuntimeProfile,
    getArtifactPaths,
    buildPseudoRawInfo,
    resolveArtifactBinaryPath,
    resolveBinaryInputContext,
    buildAnalysisArtifactContext,
    resolveLegacyArtifactFallback,
    getAnalysisCacheTarget,
    readAnalysisCacheEntry,
    writeAnalysisCacheEntry,
    resolveCachedAnalysisView,
    ensureAnalysisMappingArtifacts,
    buildDisasmArgs,
    ensureDisasmArtifacts,
    loadDisasmMapping,
    findMappingEntryByAddr,
    queryMappingWindow,
    getMappingEntrySpanLength,
    findDisasmMappingEntryByAddress,
    openDisasmAtLine,
    getBinaryAnnotationsJsonPath,
    loadBinaryHeaders,
    loadBinarySymbols,
    collectSymbolNames,
    loadOffsetToVaddr,
    ensureDiscoveredFunctionsArtifact,
    resolveAnalysisArtifactsContext,
  };
}

module.exports = { createAnalysisContext };
