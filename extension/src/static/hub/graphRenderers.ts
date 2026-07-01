// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck

function createGraphRenderers({
  panel,
  analysisCtx,
  root,
  runPythonJson,
  storageDir,
  logChannel,
  vscode,
  fs,
  path,
  getCfgScript,
  getCallGraphScript,
  getDiscoverFunctionsScript,
}) {
  const {
    resolveAnalysisArtifactsContext,
    resolveCachedAnalysisView,
    readAnalysisCacheEntry,
    writeAnalysisCacheEntry,
    ensureDiscoveredFunctionsArtifact,
    loadBinarySymbols,
  } = analysisCtx;

  const hubPost = (type, data) => panel.webview.postMessage(Object.assign({ type }, data || {}));

  const getFileSignature = (filePath) => {
    if (!filePath || !fs.existsSync(filePath)) return '';
    try {
      const stat = fs.statSync(filePath);
      return `${stat.mtimeMs}:${stat.size}`;
    } catch (_) {
      return '';
    }
  };

  const stripCacheMeta = (value) => {
    if (!value || typeof value !== 'object') return value;
    const { _cache_meta, ...rest } = value;
    return rest;
  };

  return {
    hubLoadCfg: async (message) => {
      const binaryPath = (message.binaryPath || '').trim();
      const funcAddr = String(message.funcAddr || '').trim();
      const {
        absPath,
        artifacts,
        baseName,
        mappingPath,
        discoveredPath,
        effectiveAbsPath,
        allowCache,
        hasAnalyzableBinary,
      } = await resolveAnalysisArtifactsContext({
        binaryPath,
        binaryMeta: message.binaryMeta || null,
        logPrefix: 'CFG',
        ensureMapping: true,
      });
      let functions = [];
      if (fs.existsSync(mappingPath)) {
        try {
          const mappingData = JSON.parse(fs.readFileSync(mappingPath, 'utf8'));
          const rawFunctions = mappingData.functions || [];
          const instrCount = new Map<string, number>();
          (mappingData.lines || []).forEach((line: any) => {
            if (line.function_addr) instrCount.set(line.function_addr, (instrCount.get(line.function_addr) || 0) + 1);
          });
          functions = rawFunctions
            .map((fn: any) => ({ ...fn, instrCount: instrCount.get(fn.addr) || 0 }))
            .sort((a: any, b: any) => b.instrCount - a.instrCount);
        } catch (_) {}
      }
      // Fallback: use discovered functions when mapping has no symbol info
      if (functions.length === 0 && fs.existsSync(mappingPath)) {
        try {
          let discPath = discoveredPath;
          if (!discPath || !fs.existsSync(discPath)) {
            // Run discover script on the fly
            const binForDisc = (effectiveAbsPath && fs.existsSync(effectiveAbsPath) && !fs.statSync(effectiveAbsPath).isDirectory())
              ? effectiveAbsPath
              : (absPath && fs.existsSync(absPath) && !fs.statSync(absPath).isDirectory() ? absPath : null);
            const discScript = getDiscoverFunctionsScript(root);
            const discArgs = ['--mapping', mappingPath];
            if (binForDisc) discArgs.push('--binary', binForDisc);
            const discovered = await runPythonJson(discScript, discArgs);
            if (discPath) fs.writeFileSync(discPath, JSON.stringify(discovered, null, 2), 'utf8');
            functions = (Array.isArray(discovered) ? discovered : [])
              .map((fn: any) => ({ ...fn, instrCount: 0 }))
              .sort((a: any, b: any) => (b.confidence_score || 0) - (a.confidence_score || 0));
          } else {
            const discovered = JSON.parse(fs.readFileSync(discPath, 'utf8'));
            functions = (Array.isArray(discovered) ? discovered : [])
              .map((fn: any) => ({ ...fn, instrCount: 0 }))
              .sort((a: any, b: any) => (b.confidence_score || 0) - (a.confidence_score || 0));
          }
        } catch (_) {}
      }
      if (!fs.existsSync(mappingPath)) {
        if (!hasAnalyzableBinary) {
          hubPost('hubCfg', { cfg: { blocks: [], edges: [] }, functions, funcAddr });
          return;
        }
      }
      try {
        if (fs.existsSync(mappingPath)) {
          const mappingSig = getFileSignature(mappingPath);
          const cacheKey = funcAddr ? `cfg_${funcAddr}` : 'cfg';
          const cachedCfg = readAnalysisCacheEntry(effectiveAbsPath, allowCache, cacheKey);
          if (cachedCfg && cachedCfg._cache_meta?.mapping_sig === mappingSig) {
            logChannel.appendLine(`[cache] CFG depuis cache (${funcAddr || 'full'})`);
            hubPost('hubCfg', { cfg: stripCacheMeta(cachedCfg), functions, funcAddr });
            return;
          }
          const scriptArgs = ['--mapping', mappingPath];
          if (funcAddr) scriptArgs.push('--function', funcAddr);
          const cfg = await runPythonJson(getCfgScript(root), scriptArgs);
          writeAnalysisCacheEntry(effectiveAbsPath, allowCache, cacheKey, {
            ...cfg,
            _cache_meta: { mapping_sig: mappingSig },
          });
          hubPost('hubCfg', { cfg: stripCacheMeta(cfg), functions, funcAddr });
        } else {
          logChannel.appendLine(`[CFG] Mapping introuvable: ${mappingPath}`);
          hubPost('hubCfg', { cfg: { blocks: [], edges: [] }, functions, funcAddr });
        }
      } catch (err) {
        logChannel.appendLine(`[CFG] Erreur: ${err.message}`);
        hubPost('hubCfg', { cfg: { blocks: [], edges: [] }, functions, funcAddr });
      }
    },

    hubLoadCfgForAddr: async (message) => {
      const binaryPath = (message.binaryPath || '').trim();
      const addr = (message.addr || '').trim();
      if (!addr) return;
      const {
        absPath,
        artifacts,
        mappingPath,
        discoveredPath,
        effectiveAbsPath,
        allowCache,
        hasAnalyzableBinary,
      } = await resolveAnalysisArtifactsContext({
        binaryPath,
        binaryMeta: message.binaryMeta || null,
        logPrefix: 'CFG/addr',
        ensureMapping: true,
      });
      let functions = [];
      if (fs.existsSync(mappingPath)) {
        try {
          const mappingData = JSON.parse(fs.readFileSync(mappingPath, 'utf8'));
          const rawFunctions = mappingData.functions || [];
          const instrCount = new Map<string, number>();
          (mappingData.lines || []).forEach((line: any) => {
            if (line.function_addr) instrCount.set(line.function_addr, (instrCount.get(line.function_addr) || 0) + 1);
          });
          functions = rawFunctions
            .map((fn: any) => ({ ...fn, instrCount: instrCount.get(fn.addr) || 0 }))
            .sort((a: any, b: any) => b.instrCount - a.instrCount);
        } catch (_) {}
        if (functions.length === 0) {
          try {
            let discPath = discoveredPath;
            if (!discPath || !fs.existsSync(discPath)) {
              const binForDisc = (effectiveAbsPath && fs.existsSync(effectiveAbsPath) && !fs.statSync(effectiveAbsPath).isDirectory())
                ? effectiveAbsPath
                : (absPath && fs.existsSync(absPath) && !fs.statSync(absPath).isDirectory() ? absPath : null);
              const discScript = getDiscoverFunctionsScript(root);
              const discArgs = ['--mapping', mappingPath];
              if (binForDisc) discArgs.push('--binary', binForDisc);
              const discovered = await runPythonJson(discScript, discArgs);
              if (discPath) fs.writeFileSync(discPath, JSON.stringify(discovered, null, 2), 'utf8');
              functions = (Array.isArray(discovered) ? discovered : [])
                .map((fn: any) => ({ ...fn, instrCount: 0 }))
                .sort((a: any, b: any) => (b.confidence_score || 0) - (a.confidence_score || 0));
            } else {
              const discovered = JSON.parse(fs.readFileSync(discPath, 'utf8'));
              functions = (Array.isArray(discovered) ? discovered : [])
                .map((fn: any) => ({ ...fn, instrCount: 0 }))
                .sort((a: any, b: any) => (b.confidence_score || 0) - (a.confidence_score || 0));
            }
          } catch (_) {}
        }
      }
      if (!fs.existsSync(mappingPath)) {
        if (!hasAnalyzableBinary) {
          hubPost('hubCfg', { cfg: { blocks: [], edges: [] }, functions, funcAddr: '' });
          return;
        }
      }
      try {
        if (fs.existsSync(mappingPath)) {
          const scriptArgs = ['--mapping', mappingPath, '--addr', addr];
          const cfg = await runPythonJson(getCfgScript(root), scriptArgs);
          const funcAddr = (cfg as any).func_addr || '';
          hubPost('hubCfg', { cfg: stripCacheMeta(cfg), functions, funcAddr });
        } else {
          hubPost('hubCfg', { cfg: { blocks: [], edges: [] }, functions, funcAddr: '' });
        }
      } catch (err) {
        logChannel.appendLine(`[CFG/addr] Erreur: ${err.message}`);
        hubPost('hubCfg', { cfg: { blocks: [], edges: [] }, functions, funcAddr: '' });
      }
    },

    hubLoadCallGraph: async (message) => {
      const binaryPath = (message.binaryPath || '').trim();
      const {
        absPath,
        artifacts,
        baseName,
        mappingPath,
        symbolsPath,
        discoveredPath,
        effectiveAbsPath,
        allowCache,
        hasAnalyzableBinary,
      } = await resolveAnalysisArtifactsContext({
        binaryPath,
        binaryMeta: message.binaryMeta || null,
        logPrefix: 'CallGraph',
        exampleLimit: 2,
        ensureMapping: true,
      });
      const resolvedSymbolsPath = symbolsPath;
      let resolvedDiscoveredPath = discoveredPath;
      if (!fs.existsSync(mappingPath)) {
        if (!hasAnalyzableBinary) {
          hubPost('hubCallGraph', { callGraph: { nodes: [], edges: [] } });
          return;
        }
      }
      try {
        const binForSymbols = (effectiveAbsPath && fs.existsSync(effectiveAbsPath)) ? effectiveAbsPath : absPath;
        if (artifacts?.binaryMeta?.kind === 'raw') {
          resolvedDiscoveredPath = await ensureDiscoveredFunctionsArtifact({
            artifacts,
            absPath,
            mappingPath,
            baseName,
          }) || resolvedDiscoveredPath;
          if (resolvedDiscoveredPath && fs.existsSync(resolvedDiscoveredPath)) {
            fs.writeFileSync(resolvedSymbolsPath, fs.readFileSync(resolvedDiscoveredPath, 'utf8'), 'utf8');
          } else {
            fs.writeFileSync(resolvedSymbolsPath, '[]', 'utf8');
          }
        } else if (!fs.existsSync(resolvedSymbolsPath) && fs.existsSync(binForSymbols)) {
          const symbols = await loadBinarySymbols(binForSymbols);
          fs.writeFileSync(resolvedSymbolsPath, JSON.stringify(symbols, null, 2), 'utf8');
        }
        if (fs.existsSync(mappingPath) && fs.existsSync(resolvedSymbolsPath)) {
          const mappingSig = getFileSignature(mappingPath);
          const symbolsSig = getFileSignature(resolvedSymbolsPath);
          const cachedCallGraph = readAnalysisCacheEntry(effectiveAbsPath, allowCache, 'callgraph');
          if (
            cachedCallGraph
            && cachedCallGraph._cache_meta?.mapping_sig === mappingSig
            && cachedCallGraph._cache_meta?.symbols_sig === symbolsSig
          ) {
            logChannel.appendLine('[cache] Call graph depuis cache');
            hubPost('hubCallGraph', { callGraph: stripCacheMeta(cachedCallGraph) });
            return;
          }
          const callGraph = await runPythonJson(getCallGraphScript(root), ['--mapping', mappingPath, '--symbols', resolvedSymbolsPath]);
          writeAnalysisCacheEntry(effectiveAbsPath, allowCache, 'callgraph', {
            ...callGraph,
            _cache_meta: { mapping_sig: mappingSig, symbols_sig: symbolsSig },
          });
          hubPost('hubCallGraph', { callGraph: stripCacheMeta(callGraph) });
        } else {
          logChannel.appendLine(`[CallGraph] Fichiers manquants: mapping=${fs.existsSync(mappingPath)}, symbols=${fs.existsSync(resolvedSymbolsPath)}`);
          hubPost('hubCallGraph', { callGraph: { nodes: [], edges: [] } });
        }
      } catch (err) {
        logChannel.appendLine(`[CallGraph] Erreur: ${err.message}`);
        hubPost('hubCallGraph', { callGraph: { nodes: [], edges: [] } });
      }
    },

    hubLoadDiscoveredFunctions: async (message) => {
      const binaryPath = (message.binaryPath || '').trim();
      const {
        absPath,
        artifacts,
        mappingPath,
        discoveredPath,
        effectiveAbsPath,
        allowCache,
        hasAnalyzableBinary,
      } = await resolveAnalysisArtifactsContext({
        binaryPath,
        binaryMeta: message.binaryMeta || null,
        logPrefix: 'Discovered',
        ensureMapping: true,
      });
      const resolvedDiscoveredPath = discoveredPath;
      if (!fs.existsSync(mappingPath)) {
        if (!hasAnalyzableBinary) {
          hubPost('hubDiscoveredFunctions', { functions: [] });
          return;
        }
      }
      try {
        if (!allowCache && fs.existsSync(resolvedDiscoveredPath)) {
          const rawCached = JSON.parse(fs.readFileSync(resolvedDiscoveredPath, 'utf8'));
          hubPost('hubDiscoveredFunctions', { functions: rawCached, analyzed: true });
          return;
        }
        if (fs.existsSync(mappingPath)) {
          const discScript = getDiscoverFunctionsScript(root);
          const binArg = (artifacts?.binaryMeta?.kind === 'raw')
            ? null
            : ((effectiveAbsPath && fs.existsSync(effectiveAbsPath) && !fs.statSync(effectiveAbsPath).isDirectory()) ? effectiveAbsPath : (absPath && fs.existsSync(absPath) && !fs.statSync(absPath).isDirectory() ? absPath : null));
          const args = [discScript, '--mapping', mappingPath];
          if (binArg) args.push('--binary', binArg);
          const functions = await resolveCachedAnalysisView({
            effectiveAbsPath,
            allowCache,
            cacheKey: 'discovered',
            logLabel: 'Fonctions découvertes',
            compute: async () => {
              const discovered = await runPythonJson(discScript, args.slice(1));
              if (!allowCache && artifacts?.binaryMeta?.kind === 'raw') {
                fs.writeFileSync(resolvedDiscoveredPath, JSON.stringify(discovered, null, 2), 'utf8');
              }
              return discovered;
            },
          });
          hubPost('hubDiscoveredFunctions', { functions, analyzed: true });
        } else {
          logChannel.appendLine(`[Discovered] Mapping introuvable: ${mappingPath}`);
          hubPost('hubDiscoveredFunctions', { functions: [] });
        }
      } catch (err) {
        logChannel.appendLine(`[Discovered] Erreur: ${err.message}`);
        hubPost('hubDiscoveredFunctions', { functions: [], analyzed: true, error: err.message });
      }
    },

    hubExportCfgSvg: async (message) => {
      const svg = message.svg || '';
      if (!svg) return;
      const defaultPath = path.join(storageDir, 'cfg_export.svg');
      vscode.window.showSaveDialog({
        title: 'Exporter le graphe CFG en SVG',
        defaultUri: vscode.Uri.file(defaultPath),
        filters: { 'SVG': ['svg'], 'Tous': ['*'] }
      }).then(async (saveUri) => {
        if (!saveUri) return;
        try {
          await fs.promises.writeFile(saveUri.fsPath, svg, 'utf8');
          vscode.window.showInformationMessage(`CFG exporté: ${path.basename(saveUri.fsPath)}`);
        } catch (err) {
          vscode.window.showErrorMessage(`Export échoué: ${err.message}`);
        }
      });
    },
  };
}

module.exports = { createGraphRenderers };
