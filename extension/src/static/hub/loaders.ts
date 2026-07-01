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
  }) => {
    const cacheRoot = storageDir;
    const cached = readCache(cacheRoot, absPath, cacheKey, cacheOptions);
    if (cached && isCacheUsable(cached)) {
      if (logLabel) logChannel.appendLine(`[cache] ${logLabel} depuis cache`);
      return cached;
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
        hubPost('hubSymbols', { symbols: [] });
        return;
      }
      try {
        const symbols = await resolveCachedBinaryView({
          absPath,
          cacheKey: 'symbols',
          logLabel: 'Symboles',
          compute: () => loadBinarySymbols(absPath),
        });
        hubPost('hubSymbols', { symbols });
      } catch (_) {
        hubPost('hubSymbols', { symbols: [] });
      }
    },

    hubLoadStrings: async (message) => {
      const { absPath, exists, isDirectory } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
      const minLen = Math.max(1, Math.min(64, parseInt(message.minLen, 10) || 4));
      const encoding = message.encoding || 'utf-8';
      const section = (message.section || '').trim() || null;
      if (!exists || isDirectory) {
        hubPost('hubStrings', { strings: [] });
        return;
      }
      try {
        const opts = { minLen, encoding };
        if (section) opts.section = section;
        const strings = await resolveCachedBinaryView({
          absPath,
          cacheKey: 'strings',
          cacheOptions: opts,
          logLabel: 'Strings',
          isCacheUsable: (cached) => Array.isArray(cached) && cached.length > 0,
          compute: async () => {
            const scriptPath = getStringsScript(root);
            const args = ['--binary', absPath, '--min-len', String(minLen), '--encoding', encoding];
            if (section) args.push('--section', section);
            const tmpFile = path.join(storageDir, `strings_${Date.now()}.json`);
            return runPythonJsonViaFile(scriptPath, args, tmpFile);
          },
        });
        hubPost('hubStrings', { strings });
      } catch (_) {
        hubPost('hubStrings', { strings: [] });
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
        hubPost('hubBinaryInfo', { info: { error: 'Indiquez un chemin binaire.' } });
        return;
      }
      if (!exists || isDirectory) {
        hubPost('hubBinaryInfo', { info: { error: `Binaire introuvable: ${binaryPath}` } });
        return;
      }
      try {
        if (binaryMeta.kind === 'raw') {
          hubPost('hubBinaryInfo', { info: buildPseudoRawInfo(absPath, binaryMeta.rawConfig) });
          return;
        }
        const info = await resolveCachedBinaryView({
          absPath,
          cacheKey: 'info',
          logLabel: 'Infos binaire',
          isCacheUsable: (cached) => !!(
            cached
            && cached.stripped
            && cached.stripped !== '—'
            && typeof cached.endianness === 'string'
            && cached.endianness
            && typeof cached.packers === 'string'
            && typeof cached.packer_analysis === 'object'
            && cached.packer_analysis !== null
          ),
          compute: () => loadBinaryHeaders(absPath),
        });
        hubPost('hubBinaryInfo', { info });
      } catch (err) {
        logChannel.appendLine(`[headers] ${err.message}`);
        hubPost('hubBinaryInfo', { info: { error: err.message || 'Impossible de lire les infos' } });
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
        hubPost('hubSections', { sections: [], error: 'Indiquez un chemin binaire.' });
        return;
      }
      if (!exists || isDirectory) {
        hubPost('hubSections', { sections: [], error: `Binaire introuvable: ${binaryPath}` });
        return;
      }
      try {
        if (binaryMeta.kind === 'raw') {
          const stats = fs.statSync(absPath);
          hubPost('hubSections', {
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
          compute: async () => {
            const rawSections = await runPythonJson(getSectionsScript(root), ['--binary', absPath]);
            return Array.isArray(rawSections) ? rawSections : (rawSections.sections || []);
          },
        });
        hubPost('hubSections', { sections });
      } catch (err) {
        logChannel.appendLine(`[sections] ${err.message}`);
        hubPost('hubSections', { sections: [], error: err.message });
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
            hubPost('hubXrefs', { addr, refs: [], targets: [], mode, requestKey, error: 'Mapping introuvable. Ouvrez d\'abord le désassemblage.' });
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
          addr,
          refs: parsed.refs || [],
          targets: parsed.targets || [],
          mode,
          requestKey,
        });
      } catch (err) {
        logChannel.appendLine(`[Xrefs] ${err.message}`);
        hubPost('hubXrefs', { addr, refs: [], targets: [], mode, requestKey });
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
      panel.webview.postMessage({ type: 'symbols', symbols });
    },
  };
}

module.exports = { createLoaders };
