// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck

function createLoaders({
  panel,
  analysisCtx,
  root,
  storageDir,
  runPythonJson,
  runPythonJsonViaFile,
  logChannel,
  fs,
  path,
  readCache,
  writeCache,
  getStringsScript,
  getSectionsScript,
  getXrefsScript,
}) {
  const {
    resolveBinaryInputContext,
    buildPseudoRawInfo,
    loadBinaryHeaders,
    loadBinarySymbols,
    collectSymbolNames,
    resolveAnalysisArtifactsContext,
    ensureDiscoveredFunctionsArtifact,
  } = analysisCtx;

  const resolveCachedBinaryView = async ({
    absPath,
    cacheKey,
    cacheOptions = undefined,
    logLabel = null,
    isCacheUsable = () => true,
    compute,
    useCache = true,
  }) => {
    const cacheRoot = storageDir;
    if (useCache) {
      const cached = readCache(cacheRoot, absPath, cacheKey, cacheOptions);
      if (cached && isCacheUsable(cached)) {
        if (logLabel) logChannel.appendLine(`[cache] ${logLabel} depuis cache`);
        return cached;
      }
    }
    const value = await compute();
    writeCache(cacheRoot, absPath, cacheKey, value, cacheOptions);
    return value;
  };

  const hubPost = (type, data) => panel.webview.postMessage(Object.assign({ type }, data || {}));

  return {
    hubLoadSymbols: async (message) => {
      const { absPath, exists, isDirectory } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
      if (!exists || isDirectory) {
        hubPost('hubSymbols', { binaryPath: absPath, symbols: [] });
        return;
      }
      try {
        const symbols = await resolveCachedBinaryView({
          absPath,
          cacheKey: 'symbols',
          logLabel: 'Symboles',
          useCache: message.useCache !== false,
          compute: () => loadBinarySymbols(absPath),
        });
        hubPost('hubSymbols', { binaryPath: absPath, symbols });
      } catch (_) {
        hubPost('hubSymbols', { binaryPath: absPath, symbols: [] });
      }
    },

    hubLoadStrings: async (message) => {
      const { absPath, exists, isDirectory } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
      const minLen = Math.max(1, Math.min(64, parseInt(message.minLen, 10) || 4));
      const encoding = message.encoding || 'utf-8';
      const section = (message.section || '').trim() || null;
      if (!exists || isDirectory) {
        hubPost('hubStrings', { binaryPath: absPath, strings: [] });
        return;
      }
      try {
        // Always extract and cache with BASE_MIN_LEN so switching minLen (4→8→4) never
        // triggers a re-extraction — the full base set is cached once per (encoding, section)
        // and minLen filtering is delegated to the frontend (renderStringsTable).
        // Section filtering stays in Python (uses file-offset ranges, not VA — correct for PE RVA).
        const BASE_MIN_LEN = 4;
        const extractMinLen = Math.min(minLen, BASE_MIN_LEN);
        const opts = { minLen: extractMinLen, encoding };
        if (section) opts.section = section;
        const allStrings = await resolveCachedBinaryView({
          absPath,
          cacheKey: 'strings',
          cacheOptions: opts,
          logLabel: 'Strings',
          useCache: message.useCache !== false,
          isCacheUsable: (cached) => Array.isArray(cached) && cached.length > 0,
          compute: async () => {
            const scriptPath = getStringsScript(root);
            const args = ['--binary', absPath, '--min-len', String(extractMinLen), '--encoding', encoding];
            if (section) args.push('--section', section);
            const tmpFile = path.join(storageDir, `strings_${Date.now()}.json`);
            return runPythonJsonViaFile(scriptPath, args, tmpFile);
          },
        });

        // minLen filtering is the frontend's responsibility (renderStringsTable).
        // The extension sends the full set for the requested (encoding, section) so that
        // switching minLen never requires a round-trip.
        hubPost('hubStrings', { binaryPath: absPath, strings: Array.isArray(allStrings) ? allStrings : [] });
      } catch (_) {
        hubPost('hubStrings', { binaryPath: absPath, strings: [] });
      }
    },

    hubLoadInfo: async (message) => {
      const {
        binaryPath,
        absPath,
        exists,
        isDirectory,
        binaryMeta,
      } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
      if (!binaryPath) {
        hubPost('hubBinaryInfo', { binaryPath: absPath, info: { error: 'Indiquez un chemin binaire.' } });
        return;
      }
      if (!exists || isDirectory) {
        hubPost('hubBinaryInfo', { binaryPath: absPath, info: { error: `Binaire introuvable: ${binaryPath}` } });
        return;
      }
      try {
        if (binaryMeta.kind === 'raw') {
          hubPost('hubBinaryInfo', { binaryPath: absPath, info: buildPseudoRawInfo(absPath, binaryMeta.rawConfig) });
          return;
        }
        const info = await resolveCachedBinaryView({
          absPath,
          cacheKey: 'info',
          logLabel: 'Infos binaire',
          useCache: message.useCache !== false,
          isCacheUsable: (cached) => !!(
            cached
            && cached.stripped
            && cached.stripped !== '—'
            && typeof cached.endianness === 'string'
            && cached.endianness
          ),
          compute: () => loadBinaryHeaders(absPath),
        });
        hubPost('hubBinaryInfo', { binaryPath: absPath, info });
      } catch (err) {
        logChannel.appendLine(`[headers] ${err.message}`);
        hubPost('hubBinaryInfo', { binaryPath: absPath, info: { error: err.message || 'Impossible de lire les infos' } });
      }
    },

    hubLoadSections: async (message) => {
      const {
        binaryPath,
        absPath,
        exists,
        isDirectory,
        binaryMeta,
      } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
      if (!binaryPath) {
        hubPost('hubSections', { binaryPath: absPath, sections: [], error: 'Indiquez un chemin binaire.' });
        return;
      }
      if (!exists || isDirectory) {
        hubPost('hubSections', { binaryPath: absPath, sections: [], error: `Binaire introuvable: ${binaryPath}` });
        return;
      }
      try {
        if (binaryMeta.kind === 'raw') {
          const stats = fs.statSync(absPath);
          hubPost('hubSections', {
            binaryPath: absPath,
            sections: [{
              name: 'raw',
              offset: '0x0',
              virtual_address: binaryMeta.rawConfig?.baseAddr || '0x0',
              size: stats.size,
              type: 'raw blob',
              entropy: '—',
            }],
          });
          return;
        }
        const sections = await resolveCachedBinaryView({
          absPath,
          cacheKey: 'sections',
          logLabel: 'Sections',
          useCache: message.useCache !== false,
          compute: async () => {
            const rawSections = await runPythonJson(getSectionsScript(root), ['--binary', absPath]);
            return Array.isArray(rawSections) ? rawSections : (rawSections.sections || []);
          },
        });
        hubPost('hubSections', { binaryPath: absPath, sections });
      } catch (err) {
        logChannel.appendLine(`[sections] ${err.message}`);
        hubPost('hubSections', { binaryPath: absPath, sections: [], error: err.message });
      }
    },

    hubLoadXrefs: async (message) => {
      const addr = (message.addr || '').trim();
      const binaryPath = (message.binaryPath || '').trim();
      const requestKey = (message.requestKey || '').trim();
      const {
        absPath,
        artifacts,
        baseName,
        mappingPath,
        discoveredPath,
        hasAnalyzableBinary,
      } = await resolveAnalysisArtifactsContext({
        binaryPath,
        binaryMeta: message.binaryMeta || null,
        logPrefix: 'Xrefs',
        ensureMapping: true,
      });
      const mode = (message.mode || 'to') === 'from' ? 'from' : 'to';
      if (!addr) return;
      let resolvedDiscoveredPath = discoveredPath;
      try {
        if (!fs.existsSync(mappingPath)) {
          if (!hasAnalyzableBinary) {
            hubPost('hubXrefs', { binaryPath, addr, refs: [], targets: [], mode, requestKey, error: 'Mapping introuvable. Ouvrez d\'abord le désassemblage.' });
            return;
          }
        }
        if (artifacts?.binaryMeta?.kind === 'raw' && !fs.existsSync(resolvedDiscoveredPath)) {
          resolvedDiscoveredPath = await ensureDiscoveredFunctionsArtifact({
            artifacts,
            absPath,
            mappingPath,
            baseName,
          }) || resolvedDiscoveredPath;
        }
        const parsed = await runPythonJson(getXrefsScript(root), [
          '--mapping', mappingPath,
          ...(absPath && artifacts?.binaryMeta?.kind !== 'raw' ? ['--binary', absPath] : []),
          ...(artifacts?.binaryMeta?.kind === 'raw' && fs.existsSync(resolvedDiscoveredPath) ? ['--functions', resolvedDiscoveredPath] : []),
          '--addr', addr,
          '--mode', mode,
        ]);
        hubPost('hubXrefs', {
          binaryPath,
          addr,
          refs: parsed.refs || [],
          targets: parsed.targets || [],
          mode,
          requestKey,
        });
      } catch (err) {
        logChannel.appendLine(`[Xrefs] ${err.message}`);
        hubPost('hubXrefs', { binaryPath, addr, refs: [], targets: [], mode, requestKey });
      }
    },

    getSymbols: async (message) => {
      const { absPath, exists, isDirectory } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
      let symbols = [];
      if (exists && !isDirectory) {
        try {
          symbols = collectSymbolNames(await loadBinarySymbols(absPath));
        } catch (_) { /* symbol extraction failed */ }
      }
      panel.webview.postMessage({ type: 'symbols', binaryPath: absPath, symbols });
    },
  };
}

module.exports = { createLoaders };
